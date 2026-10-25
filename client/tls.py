"""Client-side TLS context with private-CA and hostname verification enabled."""

import ssl
from pathlib import Path

from client.errors import ClientError


def create_client_context(ca_file: Path, client_cert_file: Path, client_key_file: Path) -> ssl.SSLContext:
    """Trust only ``ca_file``, require server verification, and load the device identity."""
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(ca_file))
        context.load_cert_chain(certfile=str(client_cert_file), keyfile=str(client_key_file))
        return context
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise ClientError("TLS_CONFIGURATION_ERROR", "Client TLS certificate, key, or trusted CA is invalid") from exc

