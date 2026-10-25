"""Client-side configuration independent of server implementation modules."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import socket

from client.errors import ClientError

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class ClientConfig:
    host: str
    port: int
    ca_cert_file: Path
    client_cert_file: Path
    client_key_file: Path


def _default_data_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "ZeroTrustFileSharing"
        try:
            return Path.home() / "AppData" / "Local" / "ZeroTrustFileSharing"
        except RuntimeError as exc:
            raise ClientError("CONFIGURATION_ERROR", "Cannot determine a local application data directory") from exc
    try:
        return Path.home() / ".local" / "share" / "zero-trust-file-sharing"
    except RuntimeError as exc:
        raise ClientError("CONFIGURATION_ERROR", "Cannot determine a local application data directory") from exc


def _path(raw: str | None, default: Path, variable: str) -> Path:
    try:
        value = Path(raw).expanduser() if raw else default.expanduser()
        if not value.is_absolute():
            raise ClientError("CONFIGURATION_ERROR", f"{variable} must be an absolute local path")
        resolved = value.resolve()
        try:
            resolved.relative_to(_REPOSITORY_ROOT)
        except ValueError:
            return resolved
        raise ClientError("CONFIGURATION_ERROR", f"{variable} must be outside the repository")
    except (OSError, RuntimeError) as exc:
        raise ClientError("CONFIGURATION_ERROR", f"{variable} is invalid") from exc


def _regular_file(path: Path, variable: str) -> None:
    if not path.is_file():
        raise ClientError("CONFIGURATION_ERROR", f"{variable} must name an existing regular file")
    try:
        with path.open("rb") as file:
            file.read(1)
    except OSError as exc:
        raise ClientError("CONFIGURATION_ERROR", f"{variable} is not readable") from exc


def _port(raw: str | None) -> int:
    value = raw if raw is not None else "8443"
    if not value.isascii() or not value.isdecimal() or len(value) > 5 or not 1 <= int(value) <= 65535:
        raise ClientError("CONFIGURATION_ERROR", "ZTS_PORT must be a base-10 integer in 1..65535")
    return int(value)


def _validate_local_host(host: str) -> None:
    if not host or host.strip() != host or any(ch.isspace() for ch in host):
        raise ClientError("CONFIGURATION_ERROR", "ZTS_HOST must be a local hostname or IP address")
    if host == "localhost":
        return
    try:
        addresses = {ipaddress.ip_address(item[4][0].split("%", 1)[0])
                     for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
    except (OSError, ValueError) as exc:
        raise ClientError("CONFIGURATION_ERROR", "ZTS_HOST must resolve to a local interface") from exc
    if not addresses or any(not (address.is_loopback or address.is_private or address.is_link_local)
                            for address in addresses):
        raise ClientError("CONFIGURATION_ERROR", "ZTS_HOST must resolve only to local interfaces")


def load_client_config() -> ClientConfig:
    """Validate the local mTLS client identity and its server verification CA."""
    env = os.environ
    data_dir_raw = env.get("ZTS_DATA_DIR")
    data_dir = _path(data_dir_raw, Path(data_dir_raw) if data_dir_raw else _default_data_dir(), "ZTS_DATA_DIR")
    host = env.get("ZTS_HOST", "localhost")
    _validate_local_host(host)
    port = _port(env.get("ZTS_PORT"))
    ca_cert = _path(env.get("ZTS_CA_CERT_FILE"), data_dir / "certs" / "ca.crt", "ZTS_CA_CERT_FILE")
    cert = _path(env.get("ZTS_CLIENT_CERT_FILE"), data_dir / "certs" / "client.crt", "ZTS_CLIENT_CERT_FILE")
    key = _path(env.get("ZTS_CLIENT_KEY_FILE"), data_dir / "certs" / "client.key", "ZTS_CLIENT_KEY_FILE")
    for path, name in ((ca_cert, "ZTS_CA_CERT_FILE"), (cert, "ZTS_CLIENT_CERT_FILE"),
                       (key, "ZTS_CLIENT_KEY_FILE")):
        _regular_file(path, name)
    return ClientConfig(host, port, ca_cert, cert, key)

