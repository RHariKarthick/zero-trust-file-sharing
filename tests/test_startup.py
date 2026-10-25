"""Startup ordering, bootstrap, and TLS-connection foundation tests."""

import io
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from database.core import initialize, transaction
from database.users import get_user_by_username
from security.key_store import create_encryption_key_file
from security.passwords import verify_password
from server import app as server_app
from server.bootstrap import create_first_admin
from server.config import ServerConfig
from server.dev_certs import generate_development_ca, issue_client_certificate, issue_server_certificate
from server.errors import ConfigurationError

_WORKSPACE_PARENT = Path(__file__).resolve().parents[2]


class StartupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=_WORKSPACE_PARENT)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / "application data"
        self.certs = self.data / "certs"
        self.secrets = self.data / "secrets"
        self.certs.mkdir(parents=True)
        self.secrets.mkdir()
        self.ca_key, self.ca_cert = self.certs / "ca.key", self.certs / "ca.crt"
        self.server_key, self.server_cert = self.certs / "server.key", self.certs / "server.crt"
        self.client_key, self.client_cert = self.certs / "client.key", self.certs / "client.crt"
        generate_development_ca(self.ca_key, self.ca_cert)
        issue_server_certificate(self.ca_key, self.ca_cert, self.server_key, self.server_cert, "localhost")
        issue_client_certificate(self.ca_key, self.ca_cert, self.client_key, self.client_cert, "test-device")
        create_encryption_key_file(self.secrets / "encryption.key")
        self.env = {
            "ZTS_DATA_DIR": str(self.data),
            "ZTS_DB_FILE": str(self.data / "app.sqlite3"),
            "ZTS_STORAGE_DIR": str(self.data / "storage"),
            "ZTS_CA_CERT_FILE": str(self.ca_cert),
            "ZTS_TLS_CERT_FILE": str(self.server_cert),
            "ZTS_TLS_KEY_FILE": str(self.server_key),
            "ZTS_CLIENT_CERT_FILE": str(self.client_cert),
            "ZTS_CLIENT_KEY_FILE": str(self.client_key),
            "ZTS_KEY_FILE": str(self.secrets / "encryption.key"),
        }

    def test_main_runs_startup_sequence_then_listener(self):
        with patch.dict(os.environ, self.env, clear=True), \
                patch("server.__main__.create_first_admin", return_value=None) as bootstrap, \
                patch("server.__main__.serve_forever") as serve:
            from server.__main__ import main
            main()
        bootstrap.assert_called_once_with()
        serve.assert_called_once()
        config, tls_context, encryption_key = serve.call_args.args
        self.assertEqual(config.db_file, self.data / "app.sqlite3")
        self.assertEqual(config.storage_dir, self.data / "storage")
        self.assertEqual(len(encryption_key), 32)
        self.assertEqual(tls_context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue((self.data / "app.sqlite3").is_file())
        self.assertTrue((self.data / "storage").is_dir())

    def test_missing_key_stops_before_listener_without_generating_replacement(self):
        env = {**self.env, "ZTS_KEY_FILE": str(self.secrets / "missing.key")}
        stderr = io.StringIO()
        with patch.dict(os.environ, env, clear=True), \
                patch("server.__main__.serve_forever") as serve, \
                patch("sys.stderr", stderr), self.assertRaises(SystemExit) as raised:
            from server.__main__ import main
            main()
        self.assertEqual(raised.exception.code, 1)
        serve.assert_not_called()
        self.assertFalse(Path(env["ZTS_KEY_FILE"]).exists())
        self.assertNotIn(str(self.data), stderr.getvalue())

    def test_python_module_entrypoint_fails_safely_when_certificates_are_missing(self):
        data = self.root / "empty-config"
        env = os.environ.copy()
        for name in tuple(env):
            if name.startswith("ZTS_"):
                env.pop(name)
        env.update({"ZTS_DATA_DIR": str(data), "ZTS_HOST": "localhost", "ZTS_PORT": "8443"})
        result = subprocess.run([sys.executable, "-m", "server"], cwd=Path(__file__).resolve().parents[1],
                                env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn("ZTS_CA_CERT_FILE", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(data.exists())

    def test_first_admin_is_hashed_and_audited_without_password(self):
        db_file = self.data / "bootstrap.sqlite3"
        with patch.dict(os.environ, {"ZTS_DB_FILE": str(db_file)}, clear=True):
            initialize()
            with patch("builtins.input", return_value="admin"), \
                    patch("getpass.getpass", side_effect=["a sufficiently long password", "a sufficiently long password"]):
                user_id = create_first_admin()
            self.assertIsInstance(user_id, int)
            with transaction() as conn:
                user = get_user_by_username(conn, "admin")
                audit = conn.execute("SELECT action, outcome, detail_json FROM audit_logs").fetchone()
            self.assertEqual(user["role"], "Admin")
            self.assertTrue(verify_password("a sufficiently long password", user["password_hash"]))
            self.assertEqual(audit["action"], "user.create")
            self.assertEqual(audit["outcome"], "success")
            self.assertNotIn("password", audit["detail_json"].lower())

    def test_existing_admin_is_not_prompted_again(self):
        with patch.dict(os.environ, {"ZTS_DB_FILE": str(self.data / "repeat.sqlite3")}, clear=True):
            initialize()
            with patch("builtins.input", return_value="admin"), \
                    patch("getpass.getpass", side_effect=["a sufficiently long password", "a sufficiently long password"]):
                self.assertIsNotNone(create_first_admin())
            with patch("builtins.input", side_effect=AssertionError("must not prompt")):
                self.assertIsNone(create_first_admin())

    def test_connection_slot_released_after_success_tls_and_exceptions(self):
        config = ServerConfig("localhost", 8443, self.data / "db", self.data / "storage",
                              self.ca_cert, self.server_cert, self.server_key,
                              self.secrets / "encryption.key")

        class FakeRaw:
            def __init__(self):
                self.closed = False

            def setblocking(self, flag):
                self.nonblocking = flag

            def close(self):
                self.closed = True

        class FakeTLS:
            def __init__(self):
                self.closed = False

            def setblocking(self, flag):
                self.nonblocking = flag

            def do_handshake(self):
                return None

            def close(self):
                self.closed = True

        class Context:
            def __init__(self, raises=None):
                self.raises = raises
                self.tls = FakeTLS()

            def wrap_socket(self, raw_sock, **kwargs):
                if self.raises:
                    raise self.raises
                return self.tls

        for context in (Context(), Context(ssl.SSLError("bad peer")), Context(RuntimeError("unexpected"))):
            self.assertTrue(server_app._CONNECTION_SLOTS.acquire(blocking=False))
            raw = FakeRaw()
            server_app.handle_connection(raw, ("local", 10), config, context, b"k" * 32)
            self.assertTrue(server_app._CONNECTION_SLOTS.acquire(blocking=False))
            server_app._CONNECTION_SLOTS.release()
            self.assertTrue(raw.closed or context.tls.closed)

    def test_connection_limit_is_four_under_simultaneous_acquisition(self):
        count = 8
        barrier = threading.Barrier(count)
        all_attempted = threading.Event()
        release = threading.Event()
        lock = threading.Lock()
        outcomes = []
        attempts = 0

        def contender():
            nonlocal attempts
            barrier.wait()
            acquired = server_app._CONNECTION_SLOTS.acquire(blocking=False)
            with lock:
                outcomes.append(acquired)
                attempts += 1
                if attempts == count:
                    all_attempted.set()
            if acquired:
                release.wait(timeout=2)
                server_app._CONNECTION_SLOTS.release()

        workers = [threading.Thread(target=contender) for _ in range(count)]
        for worker in workers:
            worker.start()
        self.assertTrue(all_attempted.wait(timeout=3))
        self.assertEqual(sum(outcomes), 4)
        release.set()
        for worker in workers:
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
        self.assertTrue(all(server_app._CONNECTION_SLOTS.acquire(blocking=False) for _ in range(4)))
        for _ in range(4):
            server_app._CONNECTION_SLOTS.release()

    def test_handshake_timeout_uses_one_absolute_deadline(self):
        class FakeTLS:
            def __init__(self):
                self.calls = 0

            def setblocking(self, flag):
                pass

            def do_handshake(self):
                self.calls += 1
                raise ssl.SSLWantReadError()

        tls = FakeTLS()
        with patch("server.app.time.monotonic", side_effect=[10.0, 10.1]), \
                patch("server.app.select.select", return_value=([], [], [])) as wait:
            with self.assertRaises(TimeoutError):
                server_app._perform_handshake(tls)
        self.assertEqual(wait.call_args.args[3], 4.9)


if __name__ == "__main__":
    unittest.main()
