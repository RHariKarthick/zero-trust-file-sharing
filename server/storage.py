"""Local encrypted-object storage with safe IDs and atomic publication."""

from __future__ import annotations

import os
from pathlib import Path
import re
import tempfile
import threading
import uuid

from server.errors import StorageError

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_STORAGE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_TEMP_PREFIX = ".zts-upload-"
_PUBLISH_LOCK = threading.Lock()


def _storage_root(storage_dir: Path) -> Path:
    try:
        root = Path(storage_dir).expanduser()
        if not root.is_absolute():
            raise StorageError("Storage directory must be an absolute local path")
        resolved = root.resolve()
        try:
            resolved.relative_to(_REPOSITORY_ROOT)
        except ValueError:
            return resolved
        raise StorageError("Storage directory must be outside the repository")
    except (OSError, RuntimeError) as exc:
        raise StorageError("Storage directory is invalid") from exc


def _object_path(storage_dir: Path, storage_id: str) -> Path:
    if not isinstance(storage_id, str) or not _STORAGE_ID_RE.fullmatch(storage_id):
        raise StorageError("Storage identifier is invalid")
    root = _storage_root(storage_dir)
    if not root.is_dir():
        raise StorageError("Storage directory is not initialized")
    return root / storage_id


def initialize_storage(storage_dir: Path) -> None:
    """Create the outside-repository storage directory if it does not exist."""
    root = _storage_root(storage_dir)
    try:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not root.is_dir():
            raise StorageError("Storage path is not a directory")
    except StorageError:
        raise
    except OSError as exc:
        raise StorageError("Storage directory could not be initialized") from exc


def new_storage_id() -> str:
    return uuid.uuid4().hex


def write_encrypted(storage_dir: Path, storage_id: str, ciphertext: bytes) -> None:
    """Write bytes to a same-directory temporary file and atomically publish."""
    target = _object_path(storage_dir, storage_id)
    if not isinstance(ciphertext, bytes):
        raise StorageError("Encrypted file data must be bytes")
    temporary_path: Path | None = None
    try:
        fd, raw_temp_path = tempfile.mkstemp(prefix=_TEMP_PREFIX, suffix=".tmp", dir=target.parent)
        temporary_path = Path(raw_temp_path)
        with os.fdopen(fd, "wb") as output:
            if output.write(ciphertext) != len(ciphertext):
                raise OSError("short storage write")
            output.flush()
            os.fsync(output.fileno())
        with _PUBLISH_LOCK:
            if target.exists() or target.is_symlink():
                raise StorageError("Storage object already exists")
            os.rename(temporary_path, target)
            temporary_path = None
    except StorageError:
        raise
    except OSError as exc:
        raise StorageError("Encrypted file could not be stored") from exc
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


def read_encrypted(storage_dir: Path, storage_id: str) -> bytes:
    path = _object_path(storage_dir, storage_id)
    try:
        if path.is_symlink() or not path.is_file():
            raise StorageError("Storage object is unavailable")
        return path.read_bytes()
    except StorageError:
        raise
    except OSError as exc:
        raise StorageError("Storage object is unavailable") from exc


def remove_storage_object(storage_dir: Path, storage_id: str) -> None:
    path = _object_path(storage_dir, storage_id)
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        raise StorageError("Storage object could not be removed") from exc


def cleanup_orphans(storage_dir: Path, referenced_storage_ids: set[str], older_than_epoch: int) -> int:
    """Remove unreferenced objects and upload temporaries older than cutoff."""
    root = _storage_root(storage_dir)
    if not root.is_dir():
        raise StorageError("Storage directory is not initialized")
    if (isinstance(older_than_epoch, bool) or not isinstance(older_than_epoch, int) or
            not isinstance(referenced_storage_ids, set) or
            any(not isinstance(item, str) or not _STORAGE_ID_RE.fullmatch(item)
                for item in referenced_storage_ids)):
        raise StorageError("Storage cleanup parameters are invalid")
    removed = 0
    try:
        for item in root.iterdir():
            if item.is_dir() and not item.is_symlink():
                continue
            name = item.name
            if not (_STORAGE_ID_RE.fullmatch(name) and name not in referenced_storage_ids or
                    name.startswith(_TEMP_PREFIX) and name.endswith(".tmp")):
                continue
            if item.stat(follow_symlinks=False).st_mtime >= older_than_epoch:
                continue
            item.unlink()
            removed += 1
    except OSError as exc:
        raise StorageError("Storage cleanup failed") from exc
    return removed

