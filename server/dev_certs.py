"""Generate local development CA, server, and device certificates."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
from urllib.parse import quote

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from server.errors import ConfigurationError

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_PRIVATE_KEY_MODE = 0o600
_CERTIFICATE_DAYS = 3650


def _output_paths(paths: tuple[Path, ...]) -> tuple[Path, ...]:
    resolved_paths: list[Path] = []
    for raw_path in paths:
        try:
            path = Path(raw_path).expanduser()
            if not path.is_absolute():
                raise ConfigurationError("Certificate output paths must be absolute")
            resolved = path.resolve()
        except (OSError, RuntimeError, ValueError) as exc:
            raise ConfigurationError("Certificate output path is invalid") from exc
        try:
            resolved.relative_to(_REPOSITORY_ROOT)
        except ValueError:
            resolved_paths.append(resolved)
        else:
            raise ConfigurationError("Certificate outputs must be outside the repository")
    if len(set(resolved_paths)) != len(resolved_paths):
        raise ConfigurationError("Certificate output paths must be distinct")
    if any(path.exists() for path in resolved_paths):
        raise ConfigurationError("Certificate output already exists; refusing to overwrite")
    for path in resolved_paths:
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as exc:
            raise ConfigurationError("Certificate output directory is unavailable") from exc
    return tuple(resolved_paths)


def _write_exclusive(paths: tuple[Path, ...], contents: tuple[bytes, ...]) -> None:
    created: list[Path] = []
    try:
        for path, content in zip(paths, contents, strict=True):
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            fd = os.open(path, flags, _PRIVATE_KEY_MODE)
            created.append(path)
            with os.fdopen(fd, "wb") as output:
                if output.write(content) != len(content):
                    raise OSError("short certificate output write")
                output.flush()
                os.fsync(output.fileno())
    except FileExistsError as exc:
        for path in created:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        raise ConfigurationError("Certificate output already exists; refusing to overwrite") from exc
    except OSError as exc:
        for path in created:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        raise ConfigurationError("Certificate output could not be written") from exc


def _serialize_private_key(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _load_ca(ca_key_path: Path, ca_cert_path: Path) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    try:
        private_key = serialization.load_pem_private_key(Path(ca_key_path).read_bytes(), password=None)
        certificate = x509.load_pem_x509_certificate(Path(ca_cert_path).read_bytes())
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        now = datetime.now(timezone.utc)
        if (not isinstance(private_key, ec.EllipticCurvePrivateKey) or not constraints.ca or
                certificate.not_valid_before_utc > now or certificate.not_valid_after_utc <= now):
            raise ValueError("invalid CA")
        cert_public = certificate.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_public = private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if cert_public != key_public:
            raise ValueError("CA key mismatch")
        return private_key, certificate
    except Exception as exc:
        raise ConfigurationError("Local CA certificate or key is invalid") from exc


def _issued_builder(subject: x509.Name, issuer: x509.Certificate, public_key: ec.EllipticCurvePublicKey):
    now = datetime.now(timezone.utc)
    return (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before((now - timedelta(minutes=5)).replace(tzinfo=None))
            .not_valid_after((now + timedelta(days=_CERTIFICATE_DAYS)).replace(tzinfo=None))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.public_key()), critical=False))


def generate_development_ca(ca_key_path: Path, ca_cert_path: Path) -> None:
    """Create a local P-256 root CA with exclusive outputs and no replacement."""
    paths = _output_paths((ca_key_path, ca_cert_path))
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Zero Trust Development Root CA")])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder()
                   .subject_name(subject).issuer_name(subject).public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before((now - timedelta(minutes=5)).replace(tzinfo=None))
                   .not_valid_after((now + timedelta(days=_CERTIFICATE_DAYS)).replace(tzinfo=None))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                   .add_extension(x509.KeyUsage(
                       digital_signature=True, content_commitment=False, key_encipherment=False,
                       data_encipherment=False, key_agreement=False, key_cert_sign=True,
                       crl_sign=True, encipher_only=None, decipher_only=None,
                   ), critical=True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                   .sign(key, hashes.SHA256()))
    _write_exclusive(paths, (_serialize_private_key(key), certificate.public_bytes(serialization.Encoding.PEM)))


def issue_server_certificate(
    ca_key_path: Path,
    ca_cert_path: Path,
    server_key_path: Path,
    server_cert_path: Path,
    hostname: str,
) -> None:
    """Issue a serverAuth certificate with hostname and loopback SANs."""
    if not isinstance(hostname, str) or not hostname or hostname.strip() != hostname or any(ch.isspace() for ch in hostname):
        raise ConfigurationError("Server certificate hostname is invalid")
    paths = _output_paths((server_key_path, server_cert_path))
    ca_key, ca_cert = _load_ca(ca_key_path, ca_cert_path)
    key = ec.generate_private_key(ec.SECP256R1())
    sans: list[x509.GeneralName] = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                                    x509.IPAddress(ipaddress.ip_address("::1"))]
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            encoded_hostname = hostname.encode("idna").decode("ascii")
            if len(encoded_hostname) > 253 or any(not label or len(label) > 63
                                                  for label in encoded_hostname.split(".")):
                raise ValueError("invalid DNS name")
            name = x509.DNSName(encoded_hostname)
        except (UnicodeError, ValueError) as exc:
            raise ConfigurationError("Server certificate hostname is invalid") from exc
    else:
        name = x509.IPAddress(ip)
    if name not in sans:
        sans.append(name)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname[:64])])
    certificate = (_issued_builder(subject, ca_cert, key.public_key())
                   .add_extension(x509.SubjectAlternativeName(sans), critical=False)
                   .add_extension(x509.KeyUsage(
                       digital_signature=True, content_commitment=False, key_encipherment=False,
                       data_encipherment=False, key_agreement=False, key_cert_sign=False,
                       crl_sign=False, encipher_only=None, decipher_only=None,
                   ), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                   .sign(ca_key, hashes.SHA256()))
    _write_exclusive(paths, (_serialize_private_key(key), certificate.public_bytes(serialization.Encoding.PEM)))


def issue_client_certificate(
    ca_key_path: Path,
    ca_cert_path: Path,
    client_key_path: Path,
    client_cert_path: Path,
    client_name: str,
) -> None:
    """Issue a clientAuth device certificate; its subject grants no app identity/role."""
    try:
        valid_name = (isinstance(client_name, str) and bool(client_name) and
                      len(client_name.encode("utf-8")) <= 64 and
                      not any(ord(ch) < 32 or ord(ch) == 127 for ch in client_name))
    except UnicodeEncodeError:
        valid_name = False
    if not valid_name:
        raise ConfigurationError("Client certificate device name is invalid")
    paths = _output_paths((client_key_path, client_cert_path))
    ca_key, ca_cert = _load_ca(ca_key_path, ca_cert_path)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, client_name)])
    device_uri = x509.UniformResourceIdentifier("urn:zts:device:" + quote(client_name, safe=""))
    certificate = (_issued_builder(subject, ca_cert, key.public_key())
                   .add_extension(x509.SubjectAlternativeName([device_uri]), critical=False)
                   .add_extension(x509.KeyUsage(
                       digital_signature=True, content_commitment=False, key_encipherment=False,
                       data_encipherment=False, key_agreement=False, key_cert_sign=False,
                       crl_sign=False, encipher_only=None, decipher_only=None,
                   ), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                   .sign(ca_key, hashes.SHA256()))
    _write_exclusive(paths, (_serialize_private_key(key), certificate.public_bytes(serialization.Encoding.PEM)))

