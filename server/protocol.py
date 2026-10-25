"""Length-prefixed control and binary frames with bounded socket I/O."""

from __future__ import annotations

import json
import socket
import time
from typing import BinaryIO

from server.errors import ProtocolError

MAX_CONTROL_FRAME_BYTES = 1_048_576
MAX_FILE_BYTES = 52_428_800
CONTROL_TIMEOUT_SECONDS = 10.0
BINARY_INACTIVITY_TIMEOUT_SECONDS = 30.0
BINARY_TRANSFER_TOTAL_TIMEOUT_SECONDS = 120.0
_IO_CHUNK_BYTES = 64 * 1024


def _read_exact(
    sock: socket.socket,
    size: int,
    deadline: float,
    inactivity_deadline: float | None = None,
) -> bytes:
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ProtocolError("INVALID_REQUEST", "Frame length is invalid")
    result = bytearray()
    while len(result) < size:
        now = time.monotonic()
        active_deadline = deadline
        if inactivity_deadline is not None:
            active_deadline = min(active_deadline, inactivity_deadline)
        remaining = active_deadline - now
        if remaining <= 0:
            raise ProtocolError("TRANSFER_INCOMPLETE", "Transfer deadline exceeded")
        try:
            sock.settimeout(remaining)
            chunk = sock.recv(min(size - len(result), _IO_CHUNK_BYTES))
        except (socket.timeout, TimeoutError) as exc:
            raise ProtocolError("TRANSFER_INCOMPLETE", "Transfer deadline exceeded") from exc
        except OSError as exc:
            raise ProtocolError("TRANSFER_INCOMPLETE", "Transfer could not be read") from exc
        if not chunk:
            raise ProtocolError("TRANSFER_INCOMPLETE", "Connection closed before frame completed")
        result.extend(chunk)
        if inactivity_deadline is not None:
            inactivity_deadline = time.monotonic() + BINARY_INACTIVITY_TIMEOUT_SECONDS
    return bytes(result)


def _write_all(
    sock: socket.socket,
    data: bytes,
    deadline: float,
    inactivity_deadline: float | None = None,
) -> None:
    if not isinstance(data, bytes):
        raise ProtocolError("INVALID_REQUEST", "Frame data is invalid")
    sent = 0
    while sent < len(data):
        now = time.monotonic()
        active_deadline = deadline
        if inactivity_deadline is not None:
            active_deadline = min(active_deadline, inactivity_deadline)
        remaining = active_deadline - now
        if remaining <= 0:
            raise ProtocolError("TRANSFER_INCOMPLETE", "Transfer deadline exceeded")
        try:
            sock.settimeout(remaining)
            count = sock.send(data[sent:sent + _IO_CHUNK_BYTES])
        except (socket.timeout, TimeoutError) as exc:
            raise ProtocolError("TRANSFER_INCOMPLETE", "Transfer deadline exceeded") from exc
        except OSError as exc:
            raise ProtocolError("TRANSFER_INCOMPLETE", "Transfer could not be written") from exc
        if count <= 0:
            raise ProtocolError("TRANSFER_INCOMPLETE", "Connection closed before frame completed")
        sent += count
        if inactivity_deadline is not None:
            inactivity_deadline = time.monotonic() + BINARY_INACTIVITY_TIMEOUT_SECONDS


def recv_exact(sock: socket.socket, size: int) -> bytes:
    """Read exactly ``size`` bytes, bounded by one control-frame deadline."""
    return _read_exact(sock, size, time.monotonic() + CONTROL_TIMEOUT_SECONDS)


def send_all(sock: socket.socket, data: bytes) -> None:
    """Write all bytes, bounded by one control-frame deadline."""
    _write_all(sock, data, time.monotonic() + CONTROL_TIMEOUT_SECONDS)


def recv_control(sock: socket.socket) -> dict:
    """Receive one 4-byte-length-prefixed UTF-8 JSON object."""
    deadline = time.monotonic() + CONTROL_TIMEOUT_SECONDS
    header = _read_exact(sock, 4, deadline)
    length = int.from_bytes(header, "big")
    if length == 0:
        raise ProtocolError("MALFORMED_JSON", "Control frame is empty")
    if length > MAX_CONTROL_FRAME_BYTES:
        raise ProtocolError("FRAME_TOO_LARGE", "Control frame exceeds the size limit")
    body = _read_exact(sock, length, deadline)
    def object_without_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def reject_nonfinite(value):
        raise ValueError("non-finite JSON number")

    try:
        message = json.loads(body.decode("utf-8"), object_pairs_hook=object_without_duplicates,
                             parse_constant=reject_nonfinite)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ProtocolError("MALFORMED_JSON", "Control frame is not valid UTF-8 JSON") from exc
    if not isinstance(message, dict):
        raise ProtocolError("INVALID_REQUEST", "Control message must be a JSON object")
    return message


def send_control(sock: socket.socket, message: dict) -> None:
    """Send one compact UTF-8 JSON object with a 4-byte big-endian length."""
    try:
        encoded = json.dumps(message, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise ProtocolError("INVALID_REQUEST", "Control response is not JSON serializable") from exc
    if not encoded or len(encoded) > MAX_CONTROL_FRAME_BYTES:
        raise ProtocolError("FRAME_TOO_LARGE", "Control frame exceeds the size limit")
    deadline = time.monotonic() + CONTROL_TIMEOUT_SECONDS
    _write_all(sock, len(encoded).to_bytes(4, "big") + encoded, deadline)


def recv_binary(sock: socket.socket, expected_size: int) -> bytes:
    """Read a binary frame whose header must equal the validated expected size."""
    if (isinstance(expected_size, bool) or not isinstance(expected_size, int) or
            not 0 <= expected_size <= MAX_FILE_BYTES):
        raise ProtocolError("FILE_TOO_LARGE", "File size exceeds the transfer limit")
    total_deadline = time.monotonic() + BINARY_TRANSFER_TOTAL_TIMEOUT_SECONDS
    inactivity_deadline = time.monotonic() + BINARY_INACTIVITY_TIMEOUT_SECONDS
    header = _read_exact(sock, 8, total_deadline, inactivity_deadline)
    declared_size = int.from_bytes(header, "big")
    if declared_size > MAX_FILE_BYTES:
        raise ProtocolError("FILE_TOO_LARGE", "File size exceeds the transfer limit")
    if declared_size != expected_size:
        raise ProtocolError("SIZE_MISMATCH", "Binary frame size does not match the request")
    return _read_exact(sock, declared_size, total_deadline, time.monotonic() + BINARY_INACTIVITY_TIMEOUT_SECONDS)


def send_binary(sock: socket.socket, source: BinaryIO, size_bytes: int) -> None:
    """Send an 8-byte-length-prefixed binary body from a bounded file stream."""
    if (isinstance(size_bytes, bool) or not isinstance(size_bytes, int) or
            not 0 <= size_bytes <= MAX_FILE_BYTES):
        raise ProtocolError("FILE_TOO_LARGE", "File size exceeds the transfer limit")
    total_deadline = time.monotonic() + BINARY_TRANSFER_TOTAL_TIMEOUT_SECONDS
    inactivity_deadline = time.monotonic() + BINARY_INACTIVITY_TIMEOUT_SECONDS
    _write_all(sock, size_bytes.to_bytes(8, "big"), total_deadline, inactivity_deadline)
    inactivity_deadline = time.monotonic() + BINARY_INACTIVITY_TIMEOUT_SECONDS
    remaining = size_bytes
    while remaining:
        active_deadline = min(total_deadline, inactivity_deadline)
        if active_deadline - time.monotonic() <= 0:
            raise ProtocolError("TRANSFER_INCOMPLETE", "Transfer deadline exceeded")
        try:
            chunk = source.read(min(remaining, _IO_CHUNK_BYTES))
        except OSError as exc:
            raise ProtocolError("TRANSFER_INCOMPLETE", "Transfer source could not be read") from exc
        if not chunk:
            raise ProtocolError("SIZE_MISMATCH", "Binary source ended before declared size")
        if not isinstance(chunk, bytes) or len(chunk) > remaining:
            raise ProtocolError("SIZE_MISMATCH", "Binary source size does not match declaration")
        _write_all(sock, chunk, total_deadline, inactivity_deadline)
        remaining -= len(chunk)
        inactivity_deadline = time.monotonic() + BINARY_INACTIVITY_TIMEOUT_SECONDS
    if source.read(1):
        raise ProtocolError("SIZE_MISMATCH", "Binary source exceeds declared size")
