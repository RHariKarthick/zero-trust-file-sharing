"""One-operation mutual-TLS listener and connection lifecycle."""

from __future__ import annotations

import logging
import select
import socket
import ssl
import threading
import time

from server.config import ServerConfig
from server.errors import ConfigurationError, ProtocolError
from server.handlers import handle_request
from server.protocol import recv_control, send_control

_MAX_ACTIVE_CONNECTIONS = 4
_HANDSHAKE_TIMEOUT_SECONDS = 5.0
_CONNECTION_SLOTS = threading.BoundedSemaphore(_MAX_ACTIVE_CONNECTIONS)
_LOGGER = logging.getLogger(__name__)


def _listener_for(host: str, port: int) -> socket.socket:
    try:
        candidates = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE)
        last_error: OSError | None = None
        for family, socktype, protocol, _, address in candidates:
            listener = socket.socket(family, socktype, protocol)
            try:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(address)
                listener.listen(16)
                listener.settimeout(1.0)
                return listener
            except OSError as exc:
                last_error = exc
                listener.close()
        if last_error is not None:
            raise last_error
        raise OSError("No local address was resolved")
    except OSError as exc:
        raise ConfigurationError("Local server listener could not bind to ZTS_HOST and ZTS_PORT") from exc


def _perform_handshake(tls_sock: ssl.SSLSocket) -> None:
    """Perform a nonblocking TLS handshake against one absolute monotonic deadline."""
    deadline = time.monotonic() + _HANDSHAKE_TIMEOUT_SECONDS
    tls_sock.setblocking(False)
    while True:
        try:
            tls_sock.do_handshake()
            return
        except ssl.SSLWantReadError:
            read_sockets, write_sockets = (tls_sock,), ()
        except ssl.SSLWantWriteError:
            read_sockets, write_sockets = (), (tls_sock,)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("TLS handshake deadline exceeded")
        try:
            readable, writable, _ = select.select(read_sockets, write_sockets, (), remaining)
        except (OSError, ValueError) as exc:
            raise ssl.SSLError("TLS handshake wait failed") from exc
        if not readable and not writable:
            raise TimeoutError("TLS handshake deadline exceeded")


def serve_forever(config: ServerConfig, tls_context: ssl.SSLContext, encryption_key: bytes) -> None:
    """Listen for one-operation mutual-TLS application connections."""
    if not isinstance(encryption_key, bytes) or len(encryption_key) != 32:
        raise ConfigurationError("Loaded encryption key is invalid")
    listener = _listener_for(config.host, config.port)
    _LOGGER.info("TLS listener ready on %s:%d", config.host, config.port)
    try:
        while True:
            try:
                raw_sock, peer = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not _CONNECTION_SLOTS.acquire(blocking=False):
                try:
                    raw_sock.close()
                except OSError:
                    pass
                continue
            worker = threading.Thread(
                target=handle_connection,
                args=(raw_sock, peer, config, tls_context, encryption_key),
                name="zts-mtls-handshake",
                daemon=True,
            )
            try:
                worker.start()
            except Exception:
                try:
                    raw_sock.close()
                except OSError:
                    pass
                _CONNECTION_SLOTS.release()
                _LOGGER.error("Could not start TLS connection worker")
    finally:
        listener.close()


def handle_connection(
    raw_sock: socket.socket,
    peer: tuple[str, int],
    config: ServerConfig,
    tls_context: ssl.SSLContext,
    encryption_key: bytes,
) -> None:
    """Complete device mTLS, dispatch one app operation, and always close.

    Called only for an accepted socket whose connection slot is already reserved.
    A verified certificate authenticates a device, not a user account or role.
    """
    tls_sock: ssl.SSLSocket | None = None
    try:
        raw_sock.setblocking(False)
        tls_sock = tls_context.wrap_socket(raw_sock, server_side=True, do_handshake_on_connect=False)
        _perform_handshake(tls_sock)
        try:
            request = recv_control(tls_sock)
        except ProtocolError as exc:
            if exc.code not in {"TRANSFER_INCOMPLETE"}:
                try:
                    send_control(tls_sock, {
                        "version": 1, "request_id": exc.request_id,
                        "ok": False,
                        "error": {"code": exc.code, "message": exc.message},
                    })
                except ProtocolError:
                    pass
            return
        # The client certificate authenticates a device only. Application login,
        # token validation, and role authorization happen in the handler.
        handle_request(request, peer, tls_sock, config, encryption_key)
    except (ssl.SSLError, OSError, TimeoutError):
        _LOGGER.info("TLS or application connection was rejected, timed out, or closed")
    except Exception:
        _LOGGER.error("Unexpected error while establishing a TLS connection")
    finally:
        try:
            (tls_sock if tls_sock is not None else raw_sock).close()
        except OSError:
            pass
        _CONNECTION_SLOTS.release()

