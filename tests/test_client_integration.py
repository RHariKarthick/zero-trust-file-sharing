"""Local mutually authenticated client/server operation tests."""

import io
import os
import socket
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from client import api
from client.errors import ClientError
from client.transport import upload_binary
from database.core import initialize, transaction
from database.users import create_user
from security.passwords import hash_password
from server import app as server_app
from server.config import ServerConfig
from server.dev_certs import generate_development_ca, issue_client_certificate, issue_server_certificate
from server.errors import ProtocolError
from server.storage import initialize_storage
from server.tls import create_server_context

_WORKSPACE_PARENT = Path(__file__).resolve().parents[2]


class ClientServerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(dir=_WORKSPACE_PARENT)
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.data = cls.root / "local data"
        cls.certs = cls.data / "certs"
        cls.secrets = cls.data / "secrets"
        cls.certs.mkdir(parents=True)
        cls.secrets.mkdir()
        cls.ca_key, cls.ca_cert = cls.certs / "ca.key", cls.certs / "ca.crt"
        cls.server_key, cls.server_cert = cls.certs / "server.key", cls.certs / "server.crt"
        cls.client_key, cls.client_cert = cls.certs / "client.key", cls.certs / "client.crt"
        generate_development_ca(cls.ca_key, cls.ca_cert)
        issue_server_certificate(cls.ca_key, cls.ca_cert, cls.server_key, cls.server_cert, "127.0.0.1")
        issue_client_certificate(cls.ca_key, cls.ca_cert, cls.client_key, cls.client_cert, "integration-device")
        cls.env = {
            "ZTS_DATA_DIR": str(cls.data), "ZTS_HOST": "127.0.0.1", "ZTS_PORT": "1",
            "ZTS_DB_FILE": str(cls.data / "integration.sqlite3"),
            "ZTS_STORAGE_DIR": str(cls.data / "storage"), "ZTS_CA_CERT_FILE": str(cls.ca_cert),
            "ZTS_TLS_CERT_FILE": str(cls.server_cert), "ZTS_TLS_KEY_FILE": str(cls.server_key),
            "ZTS_CLIENT_CERT_FILE": str(cls.client_cert), "ZTS_CLIENT_KEY_FILE": str(cls.client_key),
            "ZTS_KEY_FILE": str(cls.secrets / "encryption.key"),
        }
        cls.env_patch = patch.dict(os.environ, cls.env, clear=True)
        cls.env_patch.start()
        cls.addClassCleanup(cls.env_patch.stop)
        password = "integration password securely"
        cls.password = password
        cls.tls_context = create_server_context(cls.server_cert, cls.server_key, cls.ca_cert)
        cls.encryption_key = b"z" * 32
        cls.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cls.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cls.listener.bind(("127.0.0.1", 0))
        cls.listener.listen(8)
        cls.listener.settimeout(15)
        cls.port = cls.listener.getsockname()[1]
        os.environ["ZTS_PORT"] = str(cls.port)

    def setUp(self):
        self.db_file = self.data / f"integration-{uuid.uuid4().hex}.sqlite3"
        self.storage = self.data / f"storage-{uuid.uuid4().hex}"
        self.storage.mkdir()
        self.db_env_patch = patch.dict(os.environ, {"ZTS_DB_FILE": str(self.db_file)}, clear=False)
        self.db_env_patch.start()
        self.addCleanup(self.db_env_patch.stop)
        initialize()
        now = int(time.time())
        with transaction() as conn:
            self.admin_id = create_user(conn, "admin", hash_password(self.password), "Admin", now)
            self.alice_id = create_user(conn, "alice", hash_password(self.password), "User", now)
            self.bob_id = create_user(conn, "bob", hash_password(self.password), "User", now)
        self.config = ServerConfig("127.0.0.1", self.port, self.db_file, self.storage,
                                   self.ca_cert, self.server_cert, self.server_key,
                                   self.secrets / "encryption.key")

    @classmethod
    def tearDownClass(cls):
        cls.listener.close()

    def _operation(self, callback):
        result = []
        failures = []

        def serve_one():
            try:
                raw_sock, peer = self.listener.accept()
                if not server_app._CONNECTION_SLOTS.acquire(blocking=False):
                    raw_sock.close()
                    raise AssertionError("connection slot unexpectedly exhausted")
                server_app.handle_connection(raw_sock, peer, self.config,
                                             self.tls_context, self.encryption_key)
            except BaseException as exc:
                failures.append(exc)

        worker = threading.Thread(target=serve_one, daemon=True)
        worker.start()
        try:
            result.append(callback())
        except BaseException as exc:
            failures.append(exc)
        worker.join(timeout=15)
        self.assertFalse(worker.is_alive(), "server operation did not finish")
        if failures:
            raise failures[0]
        return result[0] if result else None

    def _db_files(self):
        with transaction() as conn:
            rows = conn.execute("SELECT file_id, storage_id, sha256_digest FROM files ORDER BY file_id").fetchall()
            audits = conn.execute("SELECT action, file_id, outcome FROM audit_logs ORDER BY event_id").fetchall()
        return [dict(row) for row in rows], [dict(row) for row in audits]

    def test_mtls_login_upload_share_download_revoke_delete_and_audit(self):
        admin = self._operation(lambda: api.login("admin", self.password))
        alice = self._operation(lambda: api.login("alice", self.password))
        bob = self._operation(lambda: api.login("bob", self.password))
        self.assertEqual(admin["user"]["role"], "Admin")
        source = self.root / "share me.txt"
        content = b"client-to-server encrypted at rest\x00"
        source.write_bytes(content)
        uploaded = self._operation(lambda: api.upload_file(alice["token"], source, ["bob"]))
        listing = self._operation(lambda: api.list_files(bob["token"]))
        self.assertEqual(listing[0]["file_id"], uploaded["file_id"])
        destination = self.root / "received.txt"
        downloaded = self._operation(lambda: api.download_file(bob["token"], uploaded["file_id"], destination))
        self.assertEqual(destination.read_bytes(), content)
        self.assertEqual(downloaded["sha256_hex"], uploaded["sha256_hex"])
        self._operation(lambda: api.revoke_file_access(alice["token"], uploaded["file_id"], "bob"))
        self._operation(lambda: api.grant_file_access(alice["token"], uploaded["file_id"], "bob"))
        with self.assertRaises(ClientError) as denied:
            self._operation(lambda: api.delete_file(bob["token"], uploaded["file_id"]))
        self.assertEqual(denied.exception.code, "NOT_FOUND")
        self._operation(lambda: api.revoke_file_access(alice["token"], uploaded["file_id"], "bob"))
        with self.assertRaises(ClientError) as revoked:
            self._operation(lambda: api.download_file(bob["token"], uploaded["file_id"], destination))
        self.assertEqual(revoked.exception.code, "NOT_FOUND")
        self._operation(lambda: api.delete_file(admin["token"], uploaded["file_id"]))
        files, audits = self._db_files()
        self.assertEqual(files, [])
        delete_audit = [row for row in audits if row["action"] == "file.delete"][-1]
        self.assertIsNone(delete_audit["file_id"])
        self.assertEqual(delete_audit["outcome"], "success")
        created_id = self._operation(lambda: api.admin_create_user(
            admin["token"], "charlie", self.password, "User"))
        self.assertGreater(created_id, 0)
        self._operation(lambda: api.admin_set_user_role(admin["token"], created_id, "Admin"))
        self._operation(lambda: api.admin_set_user_active(admin["token"], created_id, False))
        self._operation(lambda: api.admin_set_user_active(admin["token"], created_id, True))
        self._operation(lambda: api.logout(admin["token"]))
        with self.assertRaises(ClientError) as logged_out:
            self._operation(lambda: api.list_files(admin["token"]))
        self.assertEqual(logged_out.exception.code, "AUTH_REQUIRED")

    def test_authentication_failure_is_reported_without_skipping_mtls(self):
        with self.assertRaises(ClientError) as raised:
            self._operation(lambda: api.login("alice", "wrong password value"))
        self.assertEqual(raised.exception.code, "INVALID_CREDENTIALS")

    def test_interrupted_upload_leaves_no_metadata_or_storage_object(self):
        user = self._operation(lambda: api.login("alice", self.password))
        request = {"version": 1, "request_id": "9b20c356-d9a6-4749-a15b-9b23d5f0e571",
                   "action": "upload", "payload": {"token": user["token"], "filename": "partial.bin",
                   "size_bytes": 100, "share_with": []}}
        with self.assertRaises(ClientError) as raised:
            self._operation(lambda: upload_binary(request, io.BytesIO(b"one byte"), 100))
        self.assertEqual(raised.exception.code, "SIZE_MISMATCH")
        files, _ = self._db_files()
        self.assertEqual(files, [])
        self.assertEqual(list(self.storage.glob("[0-9a-f]" * 32)), [])
        self.assertEqual(list(self.storage.glob(".zts-upload-*.tmp")), [])

    def test_interrupted_and_tampered_downloads_preserve_destination(self):
        user = self._operation(lambda: api.login("alice", self.password))
        source = self.root / "payload.bin"
        content = b"download payload content"
        source.write_bytes(content)
        uploaded = self._operation(lambda: api.upload_file(user["token"], source))
        destination = self.root / "existing.bin"
        destination.write_bytes(b"preserve me")

        def partial_send(conn, binary_source, size_bytes):
            chunk = binary_source.read(3)
            conn.sendall(size_bytes.to_bytes(8, "big") + chunk)
            raise ProtocolError("TRANSFER_INCOMPLETE", "simulated disconnect")

        with patch("server.handlers.send_binary", side_effect=partial_send):
            with self.assertRaises(ClientError) as interrupted:
                self._operation(lambda: api.download_file(user["token"], uploaded["file_id"], destination))
        self.assertEqual(interrupted.exception.code, "TRANSFER_INCOMPLETE")
        self.assertEqual(destination.read_bytes(), b"preserve me")
        self.assertEqual(list(self.root.glob(".zts-download-*.tmp")), [])

        def tampered_send(conn, binary_source, size_bytes):
            original = binary_source.read()
            altered = bytes([original[0] ^ 1]) + original[1:]
            conn.sendall(size_bytes.to_bytes(8, "big") + altered)

        with patch("server.handlers.send_binary", side_effect=tampered_send):
            with self.assertRaises(ClientError) as integrity:
                self._operation(lambda: api.download_file(user["token"], uploaded["file_id"], destination))
        self.assertEqual(integrity.exception.code, "INTEGRITY_FAILURE")
        self.assertEqual(destination.read_bytes(), b"preserve me")
        self.assertEqual(list(self.root.glob(".zts-download-*.tmp")), [])

    def test_revoked_session_is_rejected(self):
        admin = self._operation(lambda: api.login("admin", self.password))
        bob = self._operation(lambda: api.login("bob", self.password))
        self._operation(lambda: api.admin_set_user_active(admin["token"], self.bob_id, False))
        with self.assertRaises(ClientError) as raised:
            self._operation(lambda: api.list_files(bob["token"]))
        self.assertEqual(raised.exception.code, "AUTH_REQUIRED")


if __name__ == "__main__":
    unittest.main()
