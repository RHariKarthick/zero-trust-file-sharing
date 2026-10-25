"""Opaque application session token generation and validation."""

import base64
import hashlib
import hmac
import re
from typing import Any

from security.errors import SessionError

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_VALID_ROLES = {"Admin", "User"}


def generate_token() -> str:
    """Return a URL-safe encoding of 32 cryptographically random bytes."""
    import secrets

    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def token_digest(token: str) -> bytes:
    """Return SHA-256 of the canonical ASCII token representation."""
    if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
        raise SessionError("SESSION_INVALID", "Session token is invalid")
    try:
        decoded = base64.urlsafe_b64decode(token + "=")
    except (ValueError, UnicodeEncodeError) as exc:
        raise SessionError("SESSION_INVALID", "Session token is invalid") from exc
    if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != token:
        raise SessionError("SESSION_INVALID", "Session token is invalid")
    return hashlib.sha256(token.encode("ascii")).digest()


def validate_session(token: str, session_record: dict[str, Any] | None, now_epoch: int) -> dict[str, Any]:
    """Validate a DB session record and return its safe user identity fields."""
    digest = token_digest(token)
    if isinstance(now_epoch, bool) or not isinstance(now_epoch, int) or now_epoch < 0:
        raise SessionError("SESSION_INVALID", "Session validation time is invalid")
    if not isinstance(session_record, dict):
        raise SessionError("SESSION_INVALID", "Session is invalid")
    stored_hash = session_record.get("token_hash")
    if not isinstance(stored_hash, bytes) or not hmac.compare_digest(stored_hash, digest):
        raise SessionError("SESSION_INVALID", "Session is invalid")
    if session_record.get("revoked_at") is not None:
        raise SessionError("SESSION_REVOKED", "Session has been revoked")
    created_at, expires_at = session_record.get("created_at"), session_record.get("expires_at")
    if (isinstance(created_at, bool) or not isinstance(created_at, int) or
            isinstance(expires_at, bool) or not isinstance(expires_at, int) or
            created_at < 0 or expires_at <= created_at or now_epoch < created_at):
        raise SessionError("SESSION_INVALID", "Session record is invalid")
    if now_epoch >= expires_at:
        raise SessionError("SESSION_EXPIRED", "Session has expired")
    is_active = session_record.get("is_active")
    if isinstance(is_active, bool) or not isinstance(is_active, int) or is_active != 1:
        raise SessionError("ACCOUNT_INACTIVE", "Account is inactive")
    user_id, username, role = (session_record.get("user_id"), session_record.get("username"),
                               session_record.get("role"))
    if (isinstance(user_id, bool) or not isinstance(user_id, int) or user_id <= 0 or
            not isinstance(username, str) or not username or
            not isinstance(role, str) or role not in _VALID_ROLES):
        raise SessionError("SESSION_INVALID", "Session record is invalid")
    return {"user_id": user_id, "username": username, "role": role}

