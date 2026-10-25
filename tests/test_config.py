"""Configuration tests for local client and server startup."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from client.config import load_client_config
from client.errors import ClientError
from server.config import ConfigurationError, load_server_config

_WORKSPACE_PARENT = Path(__file__).resolve().parents[2]


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=_WORKSPACE_PARENT)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / "local data"
        (self.data / "certs").mkdir(parents=True)
        (self.data / "secrets").mkdir()
        for name in ("ca.crt", "server.crt", "server.key", "client.crt", "client.key"):
            (self.data / "certs" / name).write_bytes(b"test input")
        (self.data / "secrets" / "encryption.key").write_bytes(b"x" * 32)
        self.environment = {"ZTS_DATA_DIR": str(self.data)}

    def test_server_defaults_and_db_environment(self):
        with patch.dict(os.environ, self.environment, clear=True):
            config = load_server_config()
            self.assertEqual(config.host, "localhost")
            self.assertEqual(config.port, 8443)
            self.assertEqual(config.db_file, self.data / "app.sqlite3")
            self.assertEqual(config.storage_dir, self.data / "storage")
            self.assertEqual(os.environ["ZTS_DB_FILE"], str(config.db_file))
            self.assertEqual(config.key_file, self.data / "secrets" / "encryption.key")

    def test_client_defaults_and_overrides(self):
        with patch.dict(os.environ, self.environment, clear=True):
            config = load_client_config()
            self.assertEqual((config.host, config.port), ("localhost", 8443))
            self.assertEqual(config.ca_cert_file, self.data / "certs" / "ca.crt")
            self.assertEqual(config.client_cert_file, self.data / "certs" / "client.crt")
        overrides = {**self.environment, "ZTS_HOST": "localhost", "ZTS_PORT": "9443"}
        with patch.dict(os.environ, overrides, clear=True):
            self.assertEqual(load_client_config().port, 9443)

    def test_server_rejects_invalid_port_relative_and_repository_paths(self):
        for override in ({"ZTS_PORT": "0"}, {"ZTS_PORT": "8x"},
                         {"ZTS_STORAGE_DIR": "relative/storage"},
                         {"ZTS_DB_FILE": str(Path(__file__).resolve().parents[1] / "unsafe.db")}):
            with self.subTest(override=override), patch.dict(os.environ, {**self.environment, **override}, clear=True):
                with self.assertRaises(ConfigurationError):
                    load_server_config()

    def test_client_rejects_invalid_port_and_missing_certificate(self):
        for override in ({"ZTS_PORT": "65536"}, {"ZTS_CLIENT_CERT_FILE": str(self.data / "absent.crt")}):
            with self.subTest(override=override), patch.dict(os.environ, {**self.environment, **override}, clear=True):
                with self.assertRaises(ClientError):
                    load_client_config()

    def test_server_rejects_missing_required_certificate_or_key(self):
        for variable in ("ZTS_CA_CERT_FILE", "ZTS_TLS_CERT_FILE", "ZTS_TLS_KEY_FILE", "ZTS_KEY_FILE"):
            with self.subTest(variable=variable):
                values = {**self.environment, variable: str(self.data / "absent")}
                with patch.dict(os.environ, values, clear=True), self.assertRaises(ConfigurationError):
                    load_server_config()


if __name__ == "__main__":
    unittest.main()
