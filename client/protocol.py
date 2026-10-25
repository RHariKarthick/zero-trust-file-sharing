"""Client-side framing, deliberately independent from server modules."""

from __future__ import annotations

import hashlib
import json
import socket
import time
from typing import BinaryIO

from client.errors import ClientError

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
        raise ClientError("MALFORMED_RESPONSE", "Frame length is invalid")
    output = bytearray()
    while len(output) < size:
        active_deadline = deadline
        if inactivity_deadline is not None:
            active_deadline = min(active_deadline, inactivity_deadline)
        remaining = active_deadline - time.monotonic()
        if remaining <= 0:
            raise ClientError("TRANSFER_INCOMPLETE", "Transfer deadline exceeded")
        try:
            sock.settimeout(remaining)
            chunk = sock.recv(min(size - len(output), _IO_CHUNK_BYTES))
        except (socket.timeout, TimeoutError) as exc:
            raise ClientError("TRANSFER_INCOMPLETE", "Transfer deadline exceeded") from exc
        except OSError as exc:
            raise ClientError("TRANSFER_INCOMPLETE", "Connection could not be read") from exc
        if not chunk:
            raise ClientError("TRANSFER_INCOMPLETE", "Connection closed before frame completed")
        output.extend(chunk)
        if inactivity_deadline is not None:
            inactivity_deadline = time.monotonic() + BINARY_INACTIVITY_TIMEOUT_SECONDS
    return bytes(output)


def _write_all(
    sock: socket.socket,
    data: bytes,
    deadline: float,
    inactivity_deadline: float | None = None,
) -> None:
    if not isinstance(data, bytes):
        raise ClientError("INVALID_REQUEST", "Frame data is invalid")
    offset = 0
    while offset < len(data):
        active_deadline = deadline
        if inactivity_deadline is not None:
            active_deadline = min(active_deadline, inactivity_deadline)
        remaining = active_deadline - time.monotonic()
        if remaining <= 0:
            raise ClientError("TRANSFER_INCOMPLETE", "Transfer deadline exceeded")
        try:
            sock.settimeout(remaining)
            written = sock.send(data[offset:offset + _IO_CHUNK_BYTES])
        except (socket.timeout, TimeoutError) as exc:
            raise ClientError("TRANSFER_INCOMPLETE", "Transfer deadline exceeded") from exc
        except OSError as exc:
            raise ClientError("TRANSFER_INCOMPLETE", "Connection could not be written") from exc
        if written <= 0:
            raise ClientError("TRANSFER_INCOMPLETE", "Connection closed before frame completed")
        offset += written
        if inactivity_deadline is not None:
            inactivity_deadline = time.monotonic() + BINARY_INACTIVITY_TIMEOUT_SECONDS


def recv_exact(sock: socket.socket, size: int) -> bytes:
    return _read_exact(sock, size, time.monotonic() + CONTROL_TIMEOUT_SECONDS)


def send_all(sock: socket.socket, data: bytes) -> None:
    _write_all(sock, data, time.monotonic() + CONTROL_TIMEOUT_SECONDS)


def _object_without_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_nonfinite(value):
    raise ValueError("non-finite JSON number")


def recv_control(sock: socket.socket) -> dict:
    deadline = time.monotonic() + CONTROL_TIMEOUT_SECONDS
    header = _read_exact(sock, 4, deadline)
    length = int.from_bytes(header, "big")
    if length == 0:
        raise ClientError("MALFORMED_RESPONSE", "Control response is empty")
    if length > MAX_CONTROL_FRAME_BYTES:
        raise ClientError("MALFORMED_RESPONSE", "Control response exceeds the size limit")
    body = _read_exact(sock, length, deadline)
    try:
        message = json.loads(body.decode("utf-8"), object_pairs_hook=_object_without_duplicates,
                             parse_constant=_reject_nonfinite)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ClientError("MALFORMED_RESPONSE", "Control response is invalid") from exc
    if not isinstance(message, dict):
        raise ClientError("MALFORMED_RESPONSE", "Control response must be an object")
    return message


def send_control(sock: socket.socket, message: dict) -> None:
    try:
        body = json.dumps(message, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise ClientError("INVALID_REQUEST", "Control request is invalid") from exc
    if not body or len(body) > MAX_CONTROL_FRAME_BYTES:
        raise ClientError("FRAME_TOO_LARGE", "Control request exceeds the size limit")
    _write_all(sock, len(body).to_bytes(4, "big") + body,
               time.monotonic() + CONTROL_TIMEOUT_SECONDS)


def recv_binary(sock: socket.socket, destination: BinaryIO, expected_size: int) -> tuple[int, str]:
    if (isinstance(expected_size, bool) or not isinstance(expected_size, int) or
            not 0 <= expected_size <= MAX_FILE_BYTES):
        raise ClientError("FILE_TOO_LARGE", "File size exceeds the transfer limit")
    total_deadline = time.monotonic() + BINARY_TRANSFER_TOTAL_TIMEOUT_SECONDS
    inactivity_deadline = time.monotonic() + BINARY_INACTIVITY_TIMEOUT_SECONDS
    header = _read_exact(sock, 8, total_deadline, inactivity_deadline)
    declared_size = int.from_bytes(header, "big")
    if declared_size > MAX_FILE_BYTES:
        raise ClientError("FILE_TOO_LARGE", "File size exceeds the transfer limit")
    if declared_size != expected_size:
        raise ClientError("SIZE_MISMATCH", "Binary frame size does not match metadata")
    remaining = declared_size
    digest = hashlib.sha256()
    received = 0
    inactivity_deadline = time.monotonic() + BINARY_INACTIVITY_TIMEOUT_SECONDS
    while remaining:
        active_deadline = min(total_deadline, inactivity_deadline)
        time_left = active_deadline - time.monotonic()
        if time_left <= 0:
            raise ClientError("TRANSFER_INCOMPLETE", "Transfer deadline exceeded")
        try:
            sock.settimeout(time_left)
            chunk = sock.recv(min(remaining, _IO_CHUNK_BYTES))
        except (socket.timeout, TimeoutError) as exc:
            raise ClientError("TRANSFER_INCOMPLETE", "Transfer deadline exceeded") from exc
        except OSError as exc:
            raise ClientError("TRANSFER_INCOMPLETE", "Connection could not be read") from exc
        if not chunk:
            raise ClientError("TRANSFER_INCOMPLETE", "Connection closed before binary frame completed")
        inactivity_deadline = time.monotonic() + BINARY_INACTIVITY_TIMEOUT_SECONDS
        view = memoryview(chunk)
        while view:
            try:
                written = destination.write(view)
            except OSError as exc:
                raise ClientError("TRANSFER_INCOMPLETE", "Download destination could not be written") from exc
            if written is None or written <= 0:
                raise ClientError("TRANSFER_INCOMPLETE", "Download destination could not be written")
            digest.update(view[:written])
            received += written
            view = view[written:]
        remaining -= len(chunk)
    return received, digest.hexdigest()


def send_binary(sock: socket.socket, source: BinaryIO, size_bytes: int) -> str:
    if (isinstance(size_bytes, bool) or not isinstance(size_bytes, int) or
            not 0 <= size_bytes <= MAX_FILE_BYTES):
        raise ClientError("FILE_TOO_LARGE", "File size exceeds the transfer limit")
    try:
        start = source.tell()
        source.seek(0, 2)
        end = source.tell()
        source.seek(start)
    except (AttributeError, OSError, ValueError) as exc:
        raise ClientError("INVALID_REQUEST", "Upload source must be a seekable binary file") from exc
    if end - start != size_bytes:
        raise ClientError("SIZE_MISMATCH", "Upload source size does not match declaration")
    total_deadline = time.monotonic() + BINARY_TRANSFER_TOTAL_TIMEOUT_SECONDS
    inactivity_deadline = time.monotonic() + BINARY_INACTIVITY_TIMEOUT_SECONDS
    _write_all(sock, size_bytes.to_bytes(8, "big"), total_deadline, inactivity_deadline)
    inactivity_deadline = time.monotonic() + BINARY_INACTIVITY_TIMEOUT_SECONDS
    digest = hashlib.sha256()
    remaining = size_bytes
    while remaining:
        active_deadline = min(total_deadline, inactivity_deadline)
        if active_deadline - time.monotonic() <= 0:
            raise ClientError("TRANSFER_INCOMPLETE", "Transfer deadline exceeded")
        try:
            chunk = source.read(min(remaining, _IO_CHUNK_BYTES))
        except OSError as exc:
            raise ClientError("TRANSFER_INCOMPLETE", "Upload source could not be read") from exc
        if not chunk or not isinstance(chunk, bytes) or len(chunk) > remaining:
            raise ClientError("SIZE_MISMATCH", "Upload source size does not match declaration")
        _write_all(sock, chunk, total_deadline, inactivity_deadline)
        inactivity_deadline = time.monotonic() + BINARY_INACTIVITY_TIMEOUT_SECONDS
        digest.update(chunk)
        remaining -= len(chunk)
    return digest.hexdigest()
