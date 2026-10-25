"""bcrypt password hashing and verification."""

import bcrypt

from security.errors import PasswordError

_BCRYPT_ROUNDS = 12
_MIN_PASSWORD_BYTES = 12
_MAX_PASSWORD_BYTES = 72


def _password_bytes(password: str) -> bytes:
    if not isinstance(password, str):
        raise PasswordError("INVALID_PASSWORD", "Password must be text")
    try:
        encoded = password.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise PasswordError("INVALID_PASSWORD", "Password must be valid UTF-8 text") from exc
    if not _MIN_PASSWORD_BYTES <= len(encoded) <= _MAX_PASSWORD_BYTES:
        raise PasswordError("INVALID_PASSWORD", "Password must contain 12 to 72 UTF-8 bytes")
    return encoded


def hash_password(password: str) -> bytes:
    """Return a salted bcrypt hash using cost 12."""
    try:
        return bcrypt.hashpw(_password_bytes(password), bcrypt.gensalt(rounds=_BCRYPT_ROUNDS))
    except PasswordError:
        raise
    except (ValueError, TypeError) as exc:
        raise PasswordError("INVALID_PASSWORD", "Password could not be hashed") from exc


def verify_password(password: str, password_hash: bytes) -> bool:
    """Verify a password; malformed hashes fail closed without leaking details."""
    password_bytes = _password_bytes(password)
    if not isinstance(password_hash, bytes):
        return False
    try:
        return bcrypt.checkpw(password_bytes, password_hash)
    except (ValueError, TypeError):
        return False

