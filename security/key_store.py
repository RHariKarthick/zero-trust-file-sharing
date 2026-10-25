"""Create the application's local AES key without overwriting existing files."""

import os
import secrets
from pathlib import Path

from security.errors import EncryptionError

_KEY_BYTES = 32
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _ensure_outside_repository(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(_REPOSITORY_ROOT)
    except ValueError:
        return resolved
    raise EncryptionError("KEY_PATH_IN_REPOSITORY", "Encryption key must be stored outside the repository")


def create_encryption_key_file(path: Path) -> None:
    """Create exactly 32 random bytes with exclusive creation; never overwrite."""
    target = _ensure_outside_repository(Path(path))
    key_material = secrets.token_bytes(_KEY_BYTES)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise EncryptionError("KEY_CREATE_FAILED", "Encryption key could not be created") from exc
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(target, flags, 0o600)
    except FileExistsError as exc:
        raise EncryptionError("KEY_ALREADY_EXISTS", "Encryption key file already exists") from exc
    except OSError as exc:
        raise EncryptionError("KEY_CREATE_FAILED", "Encryption key could not be created") from exc
    try:
        with os.fdopen(fd, "wb") as key_file:
            written = key_file.write(key_material)
            if written != _KEY_BYTES:
                raise OSError("short key write")
            key_file.flush()
            os.fsync(key_file.fileno())
    except OSError as exc:
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
        raise EncryptionError("KEY_CREATE_FAILED", "Encryption key could not be created") from exc

