"""Validated server configuration using local, outside-repository paths."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import socket

from server.errors import ConfigurationError

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class ServerConfig:
    host: str
    port: int
    db_file: Path
    storage_dir: Path
    ca_cert_file: Path
    tls_cert_file: Path
    tls_key_file: Path
    key_file: Path


def _default_data_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "ZeroTrustFileSharing"
        try:
            return Path.home() / "AppData" / "Local" / "ZeroTrustFileSharing"
        except RuntimeError as exc:
            raise ConfigurationError("Cannot determine a local application data directory") from exc
    try:
        return Path.home() / ".local" / "share" / "zero-trust-file-sharing"
    except RuntimeError as exc:
        raise ConfigurationError("Cannot determine a local application data directory") from exc


def _path(raw: str | None, default: Path, variable: str) -> Path:
    try:
        value = Path(raw).expanduser() if raw else default.expanduser()
        if not value.is_absolute():
            raise ConfigurationError(f"{variable} must be an absolute local path")
        resolved = value.resolve()
        try:
            resolved.relative_to(_REPOSITORY_ROOT)
        except ValueError:
            return resolved
        raise ConfigurationError(f"{variable} must be outside the repository")
    except (OSError, RuntimeError) as exc:
        raise ConfigurationError(f"{variable} is invalid") from exc


def _regular_file(path: Path, variable: str) -> None:
    if not path.is_file():
        raise ConfigurationError(f"{variable} must name an existing regular file")
    try:
        with path.open("rb") as file:
            file.read(1)
    except OSError as exc:
        raise ConfigurationError(f"{variable} is not readable") from exc


def _validate_local_host(host: str) -> None:
    if not host or host.strip() != host or any(ch.isspace() for ch in host):
        raise ConfigurationError("ZTS_HOST must be a local hostname or IP address")
    if host == "localhost":
        return
    try:
        addresses = {ipaddress.ip_address(item[4][0].split("%", 1)[0])
                     for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
    except (OSError, ValueError) as exc:
        raise ConfigurationError("ZTS_HOST must resolve to a local interface") from exc
    if not addresses or any(not (address.is_loopback or address.is_private or address.is_link_local)
                            for address in addresses):
        raise ConfigurationError("ZTS_HOST must resolve only to local interfaces")


def _port(raw: str | None) -> int:
    value = raw if raw is not None else "8443"
    if not value.isascii() or not value.isdecimal() or len(value) > 5:
        raise ConfigurationError("ZTS_PORT must be a base-10 integer in 1..65535")
    port = int(value)
    if not 1 <= port <= 65535:
        raise ConfigurationError("ZTS_PORT must be a base-10 integer in 1..65535")
    return port


def load_server_config() -> ServerConfig:
    """Resolve defaults, validate required local files, and prepare DB config."""
    env = os.environ
    data_dir_raw = env.get("ZTS_DATA_DIR")
    data_dir = _path(data_dir_raw, Path(data_dir_raw) if data_dir_raw else _default_data_dir(), "ZTS_DATA_DIR")
    host = env.get("ZTS_HOST", "localhost")
    _validate_local_host(host)
    port = _port(env.get("ZTS_PORT"))

    db_file = _path(env.get("ZTS_DB_FILE"), data_dir / "app.sqlite3", "ZTS_DB_FILE")
    storage_dir = _path(env.get("ZTS_STORAGE_DIR"), data_dir / "storage", "ZTS_STORAGE_DIR")
    ca_cert = _path(env.get("ZTS_CA_CERT_FILE"), data_dir / "certs" / "ca.crt", "ZTS_CA_CERT_FILE")
    tls_cert = _path(env.get("ZTS_TLS_CERT_FILE"), data_dir / "certs" / "server.crt", "ZTS_TLS_CERT_FILE")
    tls_key = _path(env.get("ZTS_TLS_KEY_FILE"), data_dir / "certs" / "server.key", "ZTS_TLS_KEY_FILE")
    key_file = _path(env.get("ZTS_KEY_FILE"), data_dir / "secrets" / "encryption.key", "ZTS_KEY_FILE")

    if db_file.exists() and not db_file.is_file():
        raise ConfigurationError("ZTS_DB_FILE must be a file path")
    if storage_dir.exists() and not storage_dir.is_dir():
        raise ConfigurationError("ZTS_STORAGE_DIR must be a directory path")
    for path, name in ((ca_cert, "ZTS_CA_CERT_FILE"), (tls_cert, "ZTS_TLS_CERT_FILE"),
                       (tls_key, "ZTS_TLS_KEY_FILE"), (key_file, "ZTS_KEY_FILE")):
        _regular_file(path, name)

    # database.core uses this environment variable for each transaction.
    env.setdefault("ZTS_DB_FILE", str(db_file))
    return ServerConfig(host, port, db_file, storage_dir, ca_cert, tls_cert, tls_key, key_file)

