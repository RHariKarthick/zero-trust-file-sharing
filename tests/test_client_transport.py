"""Transport response validation and temporary-download behavior."""

from contextlib import contextmanager
import hashlib
import io
import json
import socket
import ssl
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from client.errors import ClientError
from client.config import ClientConfig
from client.transport import _perform_handshake, _tls_connection, download_binary, request_control, upload_binary

_WORKSPACE_PARENT = Path(__file__).resolve().parents[2]


class MemorySocket:
    def __init__(self, incoming=b"", chunk=5):
        self.incoming = bytearray(incoming)
        self.sent = bytearray()
        self.chunk = chunk
        self.closed = False

    def settimeout(self, value):
        pass

    def recv(self, size):
        if not self.incoming:
            raise socket.timeout("stalled")
        count = min(size, self.chunk, len(self.incoming))
        value = bytes(self.incoming[:count])
        del self.incoming[:count]
        return value

    def send(self, data):
        count = min(len(data), self.chunk)
        self.sent.extend(data[:count])
        return count


def control(message):
    body = json.dumps(message, separators=(",", ":")).encode("utf-8")
    return len(body).to_bytes(4, "big") + body


def response(request_id, data=None, error=None):
    if error is None:
        message = {"version": 1, "request_id": request_id, "ok": True, "data": data}
    else:
        message = {"version": 1, "request_id": request_id, "ok": False, "error": error}
    return control(message)


class ClientTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=_WORKSPACE_PARENT)
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.request = {"version": 1, "request_id": str(uuid.uuid4()), "action": "list_files", "payload": {}}

    def _patched_connection(self, sock):
        @contextmanager
        def connection():
            try:
                yield sock
            finally:
                sock.closed = True
        return patch("client.transport._tls_connection", connection)

    def test_control_success_and_server_error_are_validated(self):
        sock = MemorySocket(response(self.request["request_id"], {"files": []}))
        with self._patched_connection(sock):
            self.assertEqual(request_control(self.request), {"files": []})
        self.assertTrue(sock.closed)

        denied = response(self.request["request_id"], error={"code": "FORBIDDEN", "message": "Access denied"})
        sock = MemorySocket(denied)
        with self._patched_connection(sock), self.assertRaises(ClientError) as raised:
            request_control(self.request)
        self.assertEqual(raised.exception.code, "FORBIDDEN")
        self.assertTrue(sock.closed)

    def test_malformed_or_mismatched_control_response_fails_closed(self):
        for wire in (
            control({"version": True, "request_id": self.request["request_id"], "ok": True, "data": {}}),
            response(str(uuid.uuid4()), {}),
            control({"version": 1, "request_id": self.request["request_id"], "ok": False,
                     "error": {"code": "UNKNOWN", "message": "bad"}}),
        ):
            sock = MemorySocket(wire)
            with self.subTest(wire=wire), self._patched_connection(sock), self.assertRaises(ClientError) as raised:
                request_control(self.request)
            self.assertEqual(raised.exception.code, "MALFORMED_RESPONSE")
            self.assertTrue(sock.closed)

    def test_response_timeout_closes_connection(self):
        sock = MemorySocket(b"\x00\x00")
        with self._patched_connection(sock), self.assertRaises(ClientError) as raised:
            request_control(self.request)
        self.assertEqual(raised.exception.code, "TRANSFER_INCOMPLETE")
        self.assertTrue(sock.closed)

    def test_tls_handshake_timeout_and_socket_cleanup(self):
        class StalledTLS:
            def setblocking(self, value):
                pass

            def do_handshake(self):
                raise ssl.SSLWantReadError()

        with patch("client.transport.time.monotonic", side_effect=[10.0, 10.0]), \
                patch("client.transport.select.select", return_value=([], [], [])):
            with self.assertRaises(ClientError) as raised:
                _perform_handshake(StalledTLS())
        self.assertEqual(raised.exception.code, "TLS_ERROR")

        class Raw:
            closed = False
            def close(self):
                self.closed = True

        class Wrapped:
            closed = False
            def close(self):
                self.closed = True

        raw, wrapped = Raw(), Wrapped()
        context = type("Context", (), {"wrap_socket": lambda *_args, **_kwargs: wrapped})()
        config = ClientConfig("localhost", 8443, Path("ca"), Path("cert"), Path("key"))
        with patch("client.transport.create_client_context", return_value=context), \
                patch("client.transport.socket.create_connection", return_value=raw), \
                patch("client.transport._perform_handshake", side_effect=ClientError("TLS_ERROR", "failed")):
            with self.assertRaises(ClientError):
                with _tls_connection(config):
                    self.fail("handshake failure must not yield a socket")
        self.assertTrue(raw.closed)
        self.assertTrue(wrapped.closed)

    def test_upload_ready_binary_final_sequence_and_digest(self):
        body = b"sample upload"
        self.request.update(action="upload", payload={"size_bytes": len(body)})
        final = {"file_id": 4, "sha256_hex": hashlib.sha256(body).hexdigest()}
        incoming = (response(self.request["request_id"], {"ready": True}) +
                    response(self.request["request_id"], final))
        sock = MemorySocket(incoming, chunk=3)
        with self._patched_connection(sock):
            self.assertEqual(upload_binary(self.request, io.BytesIO(body), len(body)), final)
        self.assertEqual(bytes(sock.sent[-(8 + len(body)):]), len(body).to_bytes(8, "big") + body)
        self.assertTrue(sock.closed)

    def test_upload_rejects_bad_ready_and_final_digest(self):
        self.request.update(action="upload", payload={"size_bytes": 1})
        sock = MemorySocket(response(self.request["request_id"], {"ready": False}))
        with self._patched_connection(sock), self.assertRaises(ClientError) as raised:
            upload_binary(self.request, io.BytesIO(b"x"), 1)
        self.assertEqual(raised.exception.code, "MALFORMED_RESPONSE")
        self.assertTrue(sock.closed)

        bad_final = {"file_id": 2, "sha256_hex": "0" * 64}
        sock = MemorySocket(response(self.request["request_id"], {"ready": True}) +
                            response(self.request["request_id"], bad_final))
        with self._patched_connection(sock), self.assertRaises(ClientError) as raised:
            upload_binary(self.request, io.BytesIO(b"x"), 1)
        self.assertEqual(raised.exception.code, "INTEGRITY_FAILURE")

    def test_download_atomically_replaces_only_after_digest_verification(self):
        body = b"verified content"
        metadata = {"filename": "stored.txt", "size_bytes": len(body),
                    "sha256_hex": hashlib.sha256(body).hexdigest()}
        wire = response(self.request["request_id"], metadata) + len(body).to_bytes(8, "big") + body
        sock = MemorySocket(wire, chunk=4)
        destination = self.directory / "download.txt"
        destination.write_bytes(b"old content")
        with self._patched_connection(sock):
            self.assertEqual(download_binary(self.request, destination), metadata)
        self.assertEqual(destination.read_bytes(), body)
        self.assertEqual(list(self.directory.glob(".zts-download-*.tmp")), [])
        self.assertTrue(sock.closed)

    def test_download_integrity_or_truncation_preserves_existing_destination_and_cleans_temp(self):
        body = b"tampered"
        metadata = {"filename": "stored.txt", "size_bytes": len(body), "sha256_hex": "0" * 64}
        destination = self.directory / "download.txt"
        destination.write_bytes(b"must remain")
        for trailer, expected_code in ((len(body).to_bytes(8, "big") + body, "INTEGRITY_FAILURE"),
                                       (len(body).to_bytes(8, "big") + body[:2], "TRANSFER_INCOMPLETE")):
            sock = MemorySocket(response(self.request["request_id"], metadata) + trailer, chunk=2)
            with self.subTest(code=expected_code), self._patched_connection(sock), self.assertRaises(ClientError) as raised:
                download_binary(self.request, destination)
            self.assertEqual(raised.exception.code, expected_code)
            self.assertEqual(destination.read_bytes(), b"must remain")
            self.assertEqual(list(self.directory.glob(".zts-download-*.tmp")), [])
            self.assertTrue(sock.closed)


if __name__ == "__main__":
    unittest.main()
