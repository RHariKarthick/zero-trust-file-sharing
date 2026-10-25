"""Server request validation, authorization, and transfer-sequence tests."""

import os
import socket
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from database.core import initialize, transaction
from database.files import list_accessible_files
from database.sessions import create_session
from database.users import create_user
from security.passwords import hash_password
from security.sessions import generate_token, token_digest
from server.config import ServerConfig
from server.handlers import handle_request
from server.protocol import recv_binary, recv_control
from server.storage import initialize_storage

_WORKSPACE_PARENT = Path(__file__).resolve().parents[2]


class MemorySocket:
    def __init__(self, incoming=b"", max_chunk=7):
        self.incoming = bytearray(incoming)
        self.sent = bytearray()
        self.max_chunk = max_chunk

    def settimeout(self, timeout):
        pass

    def recv(self, size):
        if not self.incoming:
            raise socket.timeout("no data")
        count = min(size, self.max_chunk, len(self.incoming))
        out = bytes(self.incoming[:count])
        del self.incoming[:count]
        return out

    def send(self, data):
        count = min(len(data), self.max_chunk)
        self.sent.extend(data[:count])
        return count


def make_request(action, payload, **extra):
    return {"version": 1, "request_id": str(uuid.uuid4()), "action": action,
            "payload": payload, **extra}


def response_reader(sock):
    return MemorySocket(sock.sent, max_chunk=11)


class HandlerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=_WORKSPACE_PARENT)
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.data = root / "data"
        self.storage = root / "objects"
        self.data.mkdir()
        initialize_storage(self.storage)
        self.env_patch = patch.dict(os.environ, {"ZTS_DB_FILE": str(self.data / "test.sqlite3")}, clear=True)
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        initialize()
        self.password = "a secure test password"
        with transaction() as conn:
            self.admin_id = create_user(conn, "admin", hash_password(self.password), "Admin", int(time.time()))
            self.user_id = create_user(conn, "alice", hash_password(self.password), "User", int(time.time()))
        self.admin_token = self._session(self.admin_id)
        self.user_token = self._session(self.user_id)
        self.config = ServerConfig("localhost", 8443, self.data / "test.sqlite3", self.storage,
                                   self.data / "ca.crt", self.data / "server.crt", self.data / "server.key",
                                   self.data / "enc.key")
        self.key = b"k" * 32

    def _session(self, user_id):
        token = generate_token()
        now = int(time.time())
        with transaction() as conn:
            create_session(conn, token_digest(token), user_id, now, now + 3600)
        return token

    def _call(self, request, incoming=b""):
        sock = MemorySocket(incoming)
        handle_request(request, ("127.0.0.1", 1), sock, self.config, self.key)
        return sock, response_reader(sock)

    def test_strict_envelope_and_payload_return_stable_errors(self):
        bad = make_request("list_files", {"token": self.user_token}, extra=True)
        _, reader = self._call(bad)
        response = recv_control(reader)
        self.assertEqual(response["error"]["code"], "INVALID_REQUEST")
        version = make_request("list_files", {"token": self.user_token})
        version["version"] = 2
        _, reader = self._call(version)
        response = recv_control(reader)
        self.assertEqual(response["error"]["code"], "UNSUPPORTED_VERSION")
        self.assertEqual(response["request_id"], version["request_id"])
        unsupported = make_request("unknown", {})
        _, reader = self._call(unsupported)
        response = recv_control(reader)
        self.assertEqual(response["error"]["code"], "INVALID_REQUEST")
        self.assertEqual(response["request_id"], unsupported["request_id"])
        _, reader = self._call(make_request("list_files", {"token": "bad"}))
        self.assertEqual(recv_control(reader)["error"]["code"], "AUTH_REQUIRED")

    def test_login_success_and_bad_credentials(self):
        sock, reader = self._call(make_request("login", {"username": "alice", "password": self.password}))
        response = recv_control(reader)
        self.assertTrue(response["ok"])
        self.assertEqual(response["data"]["user"]["role"], "User")
        self.assertEqual(len(response["data"]["token"]), 43)
        _, reader = self._call(make_request("login", {"username": "alice", "password": "wrong password"}))
        response = recv_control(reader)
        self.assertEqual(response["error"]["code"], "INVALID_CREDENTIALS")

    def test_user_cannot_admin_and_missing_or_forbidden_file_is_nondisclosing(self):
        _, reader = self._call(make_request("admin.create_user", {
            "token": self.user_token, "username": "bob", "password": self.password, "role": "User"}))
        self.assertEqual(recv_control(reader)["error"]["code"], "FORBIDDEN")
        _, reader = self._call(make_request("download", {"token": self.user_token, "file_id": 987}))
        self.assertEqual(recv_control(reader)["error"]["code"], "NOT_FOUND")

    def test_upload_download_listing_and_shared_access(self):
        with transaction() as conn:
            recipient_id = create_user(conn, "bob", hash_password(self.password), "User", int(time.time()))
        payload = b"private content\x00"
        request = make_request("upload", {"token": self.user_token, "filename": "note.txt",
                                           "size_bytes": len(payload), "share_with": ["bob"]})
        incoming = len(payload).to_bytes(8, "big") + payload
        upload_sock, upload_reader = self._call(request, incoming)
        ready = recv_control(upload_reader)
        final = recv_control(upload_reader)
        self.assertEqual(ready["data"], {"ready": True})
        self.assertTrue(final["ok"])
        file_id = final["data"]["file_id"]
        with transaction() as conn:
            visible = list_accessible_files(conn, recipient_id, "User")
        self.assertEqual([item["file_id"] for item in visible], [file_id])
        request = make_request("download", {"token": self.user_token, "file_id": file_id})
        _, reader = self._call(request)
        metadata = recv_control(reader)
        self.assertEqual(metadata["data"]["filename"], "note.txt")
        self.assertEqual(recv_binary(reader, len(payload)), payload)
        self.assertTrue(upload_sock.sent)

    def test_upload_invalid_filename_and_incomplete_body_do_not_create_metadata(self):
        bad_name = make_request("upload", {"token": self.user_token, "filename": "../x",
                                             "size_bytes": 1, "share_with": []})
        _, reader = self._call(bad_name)
        self.assertEqual(recv_control(reader)["error"]["code"], "INVALID_FILENAME")
        request = make_request("upload", {"token": self.user_token, "filename": "ok",
                                           "size_bytes": 4, "share_with": []})
        sock, reader = self._call(request, (4).to_bytes(8, "big") + b"x")
        self.assertEqual(recv_control(reader)["data"], {"ready": True})
        self.assertEqual(recv_control(reader)["error"]["code"], "TRANSFER_INCOMPLETE")
        with transaction() as conn:
            self.assertEqual(list_accessible_files(conn, self.user_id, "User"), [])

    def test_delete_and_share_revocation_are_enforced_by_server(self):
        file_id = self._uploaded_file()
        _, grant_reader = self._call(make_request("share.grant", {
            "token": self.user_token, "file_id": file_id, "username": "admin"}))
        self.assertTrue(recv_control(grant_reader)["ok"])
        _, revoke_reader = self._call(make_request("share.revoke", {
            "token": self.user_token, "file_id": file_id, "username": "admin"}))
        self.assertTrue(recv_control(revoke_reader)["ok"])
        _, delete_reader = self._call(make_request("delete", {"token": self.user_token, "file_id": file_id}))
        self.assertTrue(recv_control(delete_reader)["ok"])

    def _uploaded_file(self):
        body = b"x"
        sock, reader = self._call(make_request("upload", {"token": self.user_token, "filename": "x",
            "size_bytes": 1, "share_with": []}), (1).to_bytes(8, "big") + body)
        recv_control(reader)
        return recv_control(reader)["data"]["file_id"]


if __name__ == "__main__":
    unittest.main()
