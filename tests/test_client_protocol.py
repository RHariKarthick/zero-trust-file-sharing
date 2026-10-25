"""Client-side framing and timeout behavior."""

import hashlib
import io
import json
import socket
import unittest
from unittest.mock import patch

from client.errors import ClientError
from client.protocol import recv_binary, recv_control, send_binary, send_control


class ScriptedSocket:
    def __init__(self, incoming=b"", chunk=2, tick=0.0, clock=None):
        self.incoming = bytearray(incoming)
        self.sent = bytearray()
        self.chunk = chunk
        self.tick = tick
        self.clock = clock

    def settimeout(self, value):
        pass

    def recv(self, size):
        if not self.incoming:
            raise socket.timeout("stalled")
        count = min(size, self.chunk, len(self.incoming))
        data = bytes(self.incoming[:count])
        del self.incoming[:count]
        if self.clock is not None:
            self.clock[0] += self.tick
        return data

    def send(self, data):
        count = min(len(data), self.chunk)
        self.sent.extend(data[:count])
        if self.clock is not None:
            self.clock[0] += self.tick
        return count


def frame(data):
    return len(data).to_bytes(4, "big") + data


class ClientProtocolTests(unittest.TestCase):
    def test_control_partial_io_round_trip_matches_server_wire(self):
        message = {"version": 1, "request_id": "abc", "ok": True, "data": {"value": "✓"}}
        body = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        sock = ScriptedSocket(frame(body), chunk=1)
        self.assertEqual(recv_control(sock), message)
        output = ScriptedSocket(chunk=1)
        send_control(output, message)
        self.assertEqual(bytes(output.sent), frame(body))

    def test_binary_streams_bytes_and_returns_count_and_digest(self):
        body = b"large-ish\x00 raw \xff content"
        incoming = len(body).to_bytes(8, "big") + body
        output = io.BytesIO()
        count, digest = recv_binary(ScriptedSocket(incoming, chunk=3), output, len(body))
        self.assertEqual((count, digest), (len(body), hashlib.sha256(body).hexdigest()))
        self.assertEqual(output.getvalue(), body)
        sent = ScriptedSocket(chunk=2)
        self.assertEqual(send_binary(sent, io.BytesIO(body), len(body)), hashlib.sha256(body).hexdigest())
        self.assertEqual(bytes(sent.sent), incoming)

    def test_binary_truncation_size_mismatch_and_source_mismatch(self):
        with self.assertRaises(ClientError) as raised:
            recv_binary(ScriptedSocket((3).to_bytes(8, "big") + b"a"), io.BytesIO(), 3)
        self.assertEqual(raised.exception.code, "TRANSFER_INCOMPLETE")
        with self.assertRaises(ClientError) as raised:
            recv_binary(ScriptedSocket((2).to_bytes(8, "big") + b"ab"), io.BytesIO(), 3)
        self.assertEqual(raised.exception.code, "SIZE_MISMATCH")
        with self.assertRaises(ClientError) as raised:
            send_binary(ScriptedSocket(), io.BytesIO(b"a"), 2)
        self.assertEqual(raised.exception.code, "SIZE_MISMATCH")

    def test_control_absolute_deadline_survives_trickle_progress(self):
        clock = [0.0]
        sock = ScriptedSocket(frame(b'{"a":1}'), chunk=1, tick=0.06, clock=clock)
        with patch("client.protocol.time.monotonic", side_effect=lambda: clock[0]), \
                patch("client.protocol.CONTROL_TIMEOUT_SECONDS", 0.1):
            with self.assertRaises(ClientError) as raised:
                recv_control(sock)
        self.assertEqual(raised.exception.code, "TRANSFER_INCOMPLETE")

    def test_binary_total_deadline_survives_progress(self):
        clock = [0.0]
        wire = (5).to_bytes(8, "big") + b"12345"
        sock = ScriptedSocket(wire, chunk=1, tick=0.06, clock=clock)
        with patch("client.protocol.time.monotonic", side_effect=lambda: clock[0]), \
                patch("client.protocol.BINARY_INACTIVITY_TIMEOUT_SECONDS", 0.2), \
                patch("client.protocol.BINARY_TRANSFER_TOTAL_TIMEOUT_SECONDS", 0.15):
            with self.assertRaises(ClientError) as raised:
                recv_binary(sock, io.BytesIO(), 5)
        self.assertEqual(raised.exception.code, "TRANSFER_INCOMPLETE")


if __name__ == "__main__":
    unittest.main()
