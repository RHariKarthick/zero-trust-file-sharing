"""AES-256-GCM file encryption with storage-ID-bound authenticated data."""

import os
import re
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from security.errors import EncryptionError

_KEY_BYTES = 32
_NONCE_BYTES = 12
_PREFIX = b"ZTSF\x01"
_STORAGE_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def _validate_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != _KEY_BYTES:
        raise EncryptionError("INVALID_KEY", "Encryption key is invalid")


def _aad(storage_id: str) -> bytes:
    if not isinstance(storage_id, str) or not _STORAGE_ID_RE.fullmatch(storage_id):
        raise EncryptionError("INVALID_STORAGE_ID", "Storage identifier is invalid")
    return b"ZTSF:v1:" + storage_id.encode("ascii")


def load_encryption_key(path: Path) -> bytes:
    try:
        key = Path(path).read_bytes()
    except OSError as exc:
        raise EncryptionError("KEY_UNAVAILABLE", "Encryption key is unavailable") from exc
    _validate_key(key)
    return key


def encrypt_file(plaintext: bytes, storage_id: str, key: bytes) -> bytes:
    _validate_key(key)
    aad = _aad(storage_id)
    if not isinstance(plaintext, bytes):
        raise EncryptionError("INVALID_PLAINTEXT", "File data is invalid")
    nonce = os.urandom(_NONCE_BYTES)
    try:
        encrypted = AESGCM(key).encrypt(nonce, plaintext, aad)
    except (ValueError, TypeError) as exc:
        raise EncryptionError("ENCRYPTION_FAILED", "File encryption failed") from exc
    return _PREFIX + nonce + encrypted


def decrypt_file(ciphertext: bytes, storage_id: str, key: bytes) -> bytes:
    _validate_key(key)
    aad = _aad(storage_id)
    if not isinstance(ciphertext, bytes) or len(ciphertext) < len(_PREFIX) + _NONCE_BYTES + 16:
        raise EncryptionError("INTEGRITY_FAILURE", "Encrypted file is invalid or has been altered")
    if not ciphertext.startswith(_PREFIX):
        raise EncryptionError("INTEGRITY_FAILURE", "Encrypted file is invalid or has been altered")
    nonce = ciphertext[len(_PREFIX):len(_PREFIX) + _NONCE_BYTES]
    encrypted = ciphertext[len(_PREFIX) + _NONCE_BYTES:]
    try:
        return AESGCM(key).decrypt(nonce, encrypted, aad)
    except (InvalidTag, ValueError, TypeError) as exc:
        raise EncryptionError("INTEGRITY_FAILURE", "Encrypted file is invalid or has been altered") from exc

