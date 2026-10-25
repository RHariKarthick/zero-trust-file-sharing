"""Isolated tests for bounded control and binary framing."""

import io
import json
import socket
import unittest
from unittest.mock import patch

from server.errors import ProtocolError
from server.protocol import (
    MAX_CONTROL_FRAME_BYTES,
    MAX_FILE_BYTES,
    recv_binary,
    recv_control,
    recv_exact,
    send_all,
    send_binary,
    send_control,
)


class ScriptedSocket:
    def __init__(self, incoming=b"", max_chunk=2, progress_tick=0.0, clock=None):
        self.incoming = bytearray(incoming)
        self.sent = bytearray()
        self.max_chunk = max_chunk
        self.progress_tick = progress_tick
        self.clock = clock
        self.timeouts = []

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def recv(self, size):
        if self.incoming:
            count = min(size, self.max_chunk, len(self.incoming))
            result = bytes(self.incoming[:count])
            del self.incoming[:count]
            if self.clock is not None:
                self.clock[0] += self.progress_tick
            return result
        raise socket.timeout("stalled")

    def send(self, data):
        count = min(len(data), self.max_chunk)
        self.sent.extend(data[:count])
        if self.clock is not None:
            self.clock[0] += self.progress_tick
        return count


def control_wire(message):
    body = json.dumps(message, separators=(",", ":")).encode("utf-8")
    return len(body).to_bytes(4, "big") + body


class ProtocolTests(unittest.TestCase):
    def test_exact_read_and_send_all_handle_partial_io(self):
        sock = ScriptedSocket(b"abcdef", max_chunk=1)
        self.assertEqual(recv_exact(sock, 6), b"abcdef")
        send_all(sock, b"uvwxyz")
        self.assertEqual(bytes(sock.sent), b"uvwxyz")

    def test_control_round_trip_uses_four_byte_big_endian_length(self):
        request = {"version": 1, "request_id": "id", "action": "login", "payload": {}}
        sock = ScriptedSocket(control_wire(request), max_chunk=1)
        self.assertEqual(recv_control(sock), request)
        output = ScriptedSocket(max_chunk=1)
        send_control(output, request)
        self.assertEqual(bytes(output.sent), control_wire(request))

    def test_control_rejects_bad_json_non_object_and_oversize(self):
        for wire, code in (
            (b"\x00\x00\x00\x01{", "MALFORMED_JSON"),
            (b"\x00\x00\x00\x02[]", "INVALID_REQUEST"),
            (b"\x00\x00\x00\x0d{\"a\":1,\"a\":2}", "MALFORMED_JSON"),
            ((MAX_CONTROL_FRAME_BYTES + 1).to_bytes(4, "big"), "FRAME_TOO_LARGE"),
            (b"\x00\x00\x00\x00", "MALFORMED_JSON"),
        ):
            with self.subTest(code=code), self.assertRaises(ProtocolError) as raised:
                recv_control(ScriptedSocket(wire))
            self.assertEqual(raised.exception.code, code)

    def test_truncated_control_header_and_body_are_disconnect_errors(self):
        for wire in (b"\x00\x00", b"\x00\x00\x00\x03{}"):
            with self.subTest(wire=wire), self.assertRaises(ProtocolError) as raised:
                recv_control(ScriptedSocket(wire))
            self.assertEqual(raised.exception.code, "TRANSFER_INCOMPLETE")

    def test_control_absolute_deadline_is_not_reset_by_trickle_progress(self):
        clock = [0.0]
        wire = b"\x00\x00\x00\x05hello"
        sock = ScriptedSocket(wire, max_chunk=1, progress_tick=0.06, clock=clock)
        with patch("server.protocol.time.monotonic", side_effect=lambda: clock[0]), \
                patch("server.protocol.CONTROL_TIMEOUT_SECONDS", 0.1):
            with self.assertRaises(ProtocolError) as raised:
                recv_control(sock)
        self.assertEqual(raised.exception.code, "TRANSFER_INCOMPLETE")
        self.assertGreater(clock[0], 0.1)

    def test_binary_round_trip_uses_eight_byte_header_and_raw_bytes(self):
        body = b"\x00\xffarbitrary\x00bytes"
        wire = len(body).to_bytes(8, "big") + body
        self.assertEqual(recv_binary(ScriptedSocket(wire, max_chunk=3), len(body)), body)
        output = ScriptedSocket(max_chunk=3)
        send_binary(output, io.BytesIO(body), len(body))
        self.assertEqual(bytes(output.sent), wire)

    def test_binary_rejects_size_mismatch_and_file_limit(self):
        for expected, wire, code in (
            (4, (3).to_bytes(8, "big") + b"abc", "SIZE_MISMATCH"),
            (0, (MAX_FILE_BYTES + 1).to_bytes(8, "big"), "FILE_TOO_LARGE"),
            (MAX_FILE_BYTES + 1, b"", "FILE_TOO_LARGE"),
        ):
            with self.subTest(code=code), self.assertRaises(ProtocolError) as raised:
                recv_binary(ScriptedSocket(wire), expected)
            self.assertEqual(raised.exception.code, code)

    def test_binary_detects_truncation_and_source_size_mismatch(self):
        with self.assertRaises(ProtocolError) as raised:
            recv_binary(ScriptedSocket((3).to_bytes(8, "big") + b"x"), 3)
        self.assertEqual(raised.exception.code, "TRANSFER_INCOMPLETE")
        with self.assertRaises(ProtocolError) as raised:
            send_binary(ScriptedSocket(), io.BytesIO(b"x"), 2)
        self.assertEqual(raised.exception.code, "SIZE_MISMATCH")
        with self.assertRaises(ProtocolError) as raised:
            send_binary(ScriptedSocket(), io.BytesIO(b"xyz"), 2)
        self.assertEqual(raised.exception.code, "SIZE_MISMATCH")

    def test_binary_inactivity_timeout(self):
        with patch("server.protocol.BINARY_INACTIVITY_TIMEOUT_SECONDS", 0.01):
            with self.assertRaises(ProtocolError) as raised:
                recv_binary(ScriptedSocket(), 0)
        self.assertEqual(raised.exception.code, "TRANSFER_INCOMPLETE")

    def test_binary_total_deadline_is_not_reset_by_progress(self):
        clock = [0.0]
        wire = (4).to_bytes(8, "big") + b"data"
        sock = ScriptedSocket(wire, max_chunk=1, progress_tick=0.06, clock=clock)
        with patch("server.protocol.time.monotonic", side_effect=lambda: clock[0]), \
                patch("server.protocol.BINARY_INACTIVITY_TIMEOUT_SECONDS", 0.2), \
                patch("server.protocol.BINARY_TRANSFER_TOTAL_TIMEOUT_SECONDS", 0.15):
            with self.assertRaises(ProtocolError) as raised:
                recv_binary(sock, 4)
        self.assertEqual(raised.exception.code, "TRANSFER_INCOMPLETE")
        self.assertGreater(clock[0], 0.15)


if __name__ == "__main__":
    unittest.main()
