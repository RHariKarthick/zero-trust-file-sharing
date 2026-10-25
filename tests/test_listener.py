"""Listener dispatch and connection-slot cleanup tests."""

import ssl
import unittest
from pathlib import Path
from unittest.mock import patch

from server import app
from server.config import ServerConfig
from server.errors import ProtocolError


class FakeSocket:
    def __init__(self):
        self.closed = False

    def setblocking(self, value):
        self.blocking = value

    def close(self):
        self.closed = True


class FakeContext:
    def __init__(self, tls):
        self.tls = tls

    def wrap_socket(self, raw, **kwargs):
        return self.tls


class ListenerDispatchTests(unittest.TestCase):
    def setUp(self):
        self.config = ServerConfig("localhost", 8443, Path("db"), Path("storage"),
                                   Path("ca"), Path("cert"), Path("key"), Path("enc"))

    def _with_slot(self):
        self.assertTrue(app._CONNECTION_SLOTS.acquire(blocking=False))
        raw, tls = FakeSocket(), FakeSocket()
        return raw, tls, FakeContext(tls)

    def test_mutual_tls_connection_dispatches_exactly_one_request_then_closes(self):
        raw, tls, context = self._with_slot()
        request = {"version": 1, "request_id": "id", "action": "login", "payload": {}}
        with patch("server.app._perform_handshake"), \
                patch("server.app.recv_control", return_value=request) as receive, \
                patch("server.app.handle_request") as dispatch:
            app.handle_connection(raw, ("127.0.0.1", 1234), self.config, context, b"k" * 32)
        receive.assert_called_once_with(tls)
        dispatch.assert_called_once_with(request, ("127.0.0.1", 1234), tls, self.config, b"k" * 32)
        self.assertTrue(tls.closed)
        self.assertTrue(app._CONNECTION_SLOTS.acquire(blocking=False))
        app._CONNECTION_SLOTS.release()

    def test_malformed_control_gets_one_best_effort_error_and_closes(self):
        raw, tls, context = self._with_slot()
        error = ProtocolError("MALFORMED_JSON", "bad JSON")
        with patch("server.app._perform_handshake"), \
                patch("server.app.recv_control", side_effect=error), \
                patch("server.app.send_control") as send, \
                patch("server.app.handle_request") as dispatch:
            app.handle_connection(raw, ("peer", 1), self.config, context, b"k" * 32)
        send.assert_called_once_with(tls, {
            "version": 1, "request_id": None, "ok": False,
            "error": {"code": "MALFORMED_JSON", "message": "bad JSON"},
        })
        dispatch.assert_not_called()
        self.assertTrue(tls.closed)
        self.assertTrue(app._CONNECTION_SLOTS.acquire(blocking=False))
        app._CONNECTION_SLOTS.release()

    def test_control_timeout_closes_without_second_frame_and_releases_slot(self):
        raw, tls, context = self._with_slot()
        with patch("server.app._perform_handshake"), \
                patch("server.app.recv_control", side_effect=ProtocolError("TRANSFER_INCOMPLETE", "timeout")), \
                patch("server.app.send_control") as send:
            app.handle_connection(raw, ("peer", 1), self.config, context, b"k" * 32)
        send.assert_not_called()
        self.assertTrue(tls.closed)
        self.assertTrue(app._CONNECTION_SLOTS.acquire(blocking=False))
        app._CONNECTION_SLOTS.release()


if __name__ == "__main__":
    unittest.main()
