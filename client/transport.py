"""Verified one-operation mutual-TLS transport for the client API."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import re
import select
import socket
import ssl
import tempfile
import time
import uuid
from typing import BinaryIO, Iterator

from client.config import ClientConfig, load_client_config
from client.errors import ClientError
from client.protocol import recv_binary, recv_control, send_binary, send_control
from client.tls import create_client_context

HANDSHAKE_TIMEOUT_SECONDS = 5.0
_WIRE_ERROR_CODES = {
    "INVALID_REQUEST", "UNSUPPORTED_VERSION", "MALFORMED_JSON", "FRAME_TOO_LARGE",
    "INVALID_CREDENTIALS", "AUTH_REQUIRED", "SESSION_EXPIRED", "FORBIDDEN", "NOT_FOUND",
    "CONFLICT", "INVALID_FILENAME", "FILE_TOO_LARGE", "SIZE_MISMATCH", "TRANSFER_INCOMPLETE",
    "INTEGRITY_FAILURE", "STORAGE_ERROR", "DATABASE_ERROR", "TLS_ERROR", "INTERNAL_ERROR",
}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _perform_handshake(sock: ssl.SSLSocket) -> None:
    deadline = time.monotonic() + HANDSHAKE_TIMEOUT_SECONDS
    sock.setblocking(False)
    while True:
        try:
            sock.do_handshake()
            sock.setblocking(True)
            return
        except ssl.SSLWantReadError:
            readers, writers = (sock,), ()
        except ssl.SSLWantWriteError:
            readers, writers = (), (sock,)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ClientError("TLS_ERROR", "Mutual TLS handshake timed out")
        try:
            readable, writable, _ = select.select(readers, writers, (), remaining)
        except (OSError, ValueError) as exc:
            raise ClientError("TLS_ERROR", "Mutual TLS handshake failed") from exc
        if not readable and not writable:
            raise ClientError("TLS_ERROR", "Mutual TLS handshake timed out")
        # SSLWantRead/Write is retried by do_handshake on the next loop.


@contextmanager
def _tls_connection(config: ClientConfig | None = None) -> Iterator[ssl.SSLSocket]:
    """Open, verify, yield, and close one client TLS connection."""
    config = config or load_client_config()
    raw_sock: socket.socket | None = None
    tls_sock: ssl.SSLSocket | None = None
    try:
        context = create_client_context(config.ca_cert_file, config.client_cert_file, config.client_key_file)
        try:
            raw_sock = socket.create_connection((config.host, config.port), timeout=HANDSHAKE_TIMEOUT_SECONDS)
            tls_sock = context.wrap_socket(raw_sock, server_hostname=config.host, do_handshake_on_connect=False)
            _perform_handshake(tls_sock)
        except ClientError:
            raise
        except (OSError, ssl.SSLError, TimeoutError) as exc:
            raise ClientError("TLS_ERROR", "Could not establish a verified TLS connection") from exc
        yield tls_sock
    finally:
        if tls_sock is not None:
            try:
                tls_sock.close()
            except OSError:
                pass
        if raw_sock is not None:
            try:
                raw_sock.close()
            except OSError:
                pass


def _validate_request_id(request: dict) -> str:
    if not isinstance(request, dict) or not isinstance(request.get("request_id"), str):
        raise ClientError("INVALID_REQUEST", "Request identifier is invalid")
    request_id = request["request_id"]
    try:
        parsed = uuid.UUID(request_id)
    except (ValueError, AttributeError) as exc:
        raise ClientError("INVALID_REQUEST", "Request identifier is invalid") from exc
    if parsed.version != 4 or str(parsed) != request_id.lower():
        raise ClientError("INVALID_REQUEST", "Request identifier must be UUIDv4")
    return request_id


def _read_response(sock: ssl.SSLSocket, request_id: str) -> dict:
    response = recv_control(sock)
    if not isinstance(response, dict) or response.get("version") != 1 or type(response.get("version")) is not int:
        raise ClientError("MALFORMED_RESPONSE", "Server response envelope is invalid")
    if response.get("request_id") != request_id or type(response.get("ok")) is not bool:
        raise ClientError("MALFORMED_RESPONSE", "Server response does not match the request")
    if response["ok"]:
        if set(response) != {"version", "request_id", "ok", "data"} or not isinstance(response["data"], dict):
            raise ClientError("MALFORMED_RESPONSE", "Server success response is invalid")
        return response["data"]
    error = response.get("error")
    if set(response) != {"version", "request_id", "ok", "error"} or not isinstance(error, dict):
        raise ClientError("MALFORMED_RESPONSE", "Server error response is invalid")
    code = error.get("code")
    if (set(error) != {"code", "message"} or not isinstance(code, str) or code not in _WIRE_ERROR_CODES or
            not isinstance(error.get("message"), str)):
        raise ClientError("MALFORMED_RESPONSE", "Server error response is invalid")
    raise ClientError(code, error["message"])


def request_control(request: dict) -> dict:
    request_id = _validate_request_id(request)
    with _tls_connection() as conn:
        send_control(conn, request)
        return _read_response(conn, request_id)


def upload_binary(request: dict, source: BinaryIO, size_bytes: int) -> dict:
    request_id = _validate_request_id(request)
    with _tls_connection() as conn:
        send_control(conn, request)
        ready = _read_response(conn, request_id)
        if ready != {"ready": True}:
            raise ClientError("MALFORMED_RESPONSE", "Server did not return the expected upload-ready response")
        digest = send_binary(conn, source, size_bytes)
        result = _read_response(conn, request_id)
        if (set(result) != {"file_id", "sha256_hex"} or
                isinstance(result.get("file_id"), bool) or not isinstance(result.get("file_id"), int) or
                result["file_id"] <= 0 or not isinstance(result.get("sha256_hex"), str) or
                not _SHA256_RE.fullmatch(result["sha256_hex"])):
            raise ClientError("MALFORMED_RESPONSE", "Server upload result is invalid")
        if result["sha256_hex"] != digest:
            raise ClientError("INTEGRITY_FAILURE", "Uploaded file digest did not match the server result")
        return result


def download_binary(request: dict, destination: Path) -> dict:
    request_id = _validate_request_id(request)
    destination = Path(destination).expanduser()
    temporary_path: Path | None = None
    try:
        with _tls_connection() as conn:
            send_control(conn, request)
            metadata = _read_response(conn, request_id)
            if (set(metadata) != {"filename", "size_bytes", "sha256_hex"} or
                    not isinstance(metadata.get("filename"), str) or
                    isinstance(metadata.get("size_bytes"), bool) or
                    not isinstance(metadata.get("size_bytes"), int) or
                    not 0 <= metadata["size_bytes"] <= 52_428_800 or
                    not isinstance(metadata.get("sha256_hex"), str) or
                    not _SHA256_RE.fullmatch(metadata["sha256_hex"])):
                raise ClientError("MALFORMED_RESPONSE", "Server download metadata is invalid")
            parent = destination.parent
            if not parent.is_dir():
                raise ClientError("TRANSFER_INCOMPLETE", "Download destination directory is unavailable")
            try:
                fd, raw_temp = tempfile.mkstemp(prefix=".zts-download-", suffix=".tmp", dir=parent)
                temporary_path = Path(raw_temp)
                with os.fdopen(fd, "wb") as output:
                    received, digest = recv_binary(conn, output, metadata["size_bytes"])
                    output.flush()
                    os.fsync(output.fileno())
            except ClientError:
                raise
            except OSError as exc:
                raise ClientError("TRANSFER_INCOMPLETE", "Download could not be written") from exc
            if received != metadata["size_bytes"]:
                raise ClientError("SIZE_MISMATCH", "Downloaded byte count does not match metadata")
            if digest != metadata["sha256_hex"]:
                raise ClientError("INTEGRITY_FAILURE", "Downloaded file failed SHA-256 verification")
            try:
                os.replace(temporary_path, destination)
                temporary_path = None
            except OSError as exc:
                raise ClientError("TRANSFER_INCOMPLETE", "Verified download could not replace its destination") from exc
            return metadata
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
