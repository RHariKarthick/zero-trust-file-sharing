"""Server-side TLS context configuration for mutual TLS."""

import ssl
from pathlib import Path

from server.errors import ConfigurationError


def create_server_context(cert_file: Path, key_file: Path, ca_file: Path) -> ssl.SSLContext:
    """Require a certificate trusted by the configured local CA for every client."""
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
        context.load_verify_locations(cafile=str(ca_file))
        context.verify_mode = ssl.CERT_REQUIRED
        return context
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise ConfigurationError("Server TLS certificate, key, or trusted CA is invalid") from exc

