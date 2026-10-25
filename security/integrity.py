"""SHA-256 file integrity helpers."""

import hashlib
import hmac


def sha256_digest(data: bytes) -> bytes:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return sha256_digest(data).hex()


def verify_sha256(data: bytes, expected_digest: bytes) -> bool:
    if not isinstance(data, bytes) or not isinstance(expected_digest, bytes) or len(expected_digest) != 32:
        return False
    return hmac.compare_digest(sha256_digest(data), expected_digest)

