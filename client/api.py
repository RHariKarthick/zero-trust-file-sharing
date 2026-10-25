"""Typed public operations used by the Streamlit UI."""

from __future__ import annotations

from pathlib import Path
import re
import uuid

from client.errors import ClientError
from client.transport import download_binary, request_control, upload_binary
from client.protocol import MAX_FILE_BYTES

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _request(action: str, payload: dict) -> dict:
    return {"version": 1, "request_id": str(uuid.uuid4()), "action": action, "payload": payload}


def _expect_empty(data: dict) -> None:
    if data != {}:
        raise ClientError("MALFORMED_RESPONSE", "Server response data is invalid")


def login(username: str, password: str) -> dict:
    data = request_control(_request("login", {"username": username, "password": password}))
    user = data.get("user")
    if (set(data) != {"token", "expires_at", "user"} or not isinstance(data.get("token"), str) or
            not _TOKEN_RE.fullmatch(data["token"]) or
            isinstance(data.get("expires_at"), bool) or not isinstance(data.get("expires_at"), int) or
            not isinstance(user, dict) or set(user) != {"user_id", "username", "role"} or
            isinstance(user.get("user_id"), bool) or not isinstance(user.get("user_id"), int) or
            user["user_id"] <= 0 or not isinstance(user.get("username"), str) or
            not isinstance(user.get("role"), str) or user["role"] not in {"Admin", "User"}):
        raise ClientError("MALFORMED_RESPONSE", "Server login response is invalid")
    return data


def logout(token: str) -> None:
    _expect_empty(request_control(_request("logout", {"token": token})))


def list_files(token: str) -> list[dict]:
    data = request_control(_request("list_files", {"token": token}))
    files = data.get("files")
    if set(data) != {"files"} or not isinstance(files, list):
        raise ClientError("MALFORMED_RESPONSE", "Server file listing is invalid")
    required = {"file_id", "filename", "owner_username", "size_bytes", "sha256_hex", "created_at", "access"}
    for row in files:
        if (not isinstance(row, dict) or set(row) != required or
                isinstance(row.get("file_id"), bool) or not isinstance(row.get("file_id"), int) or
                isinstance(row.get("size_bytes"), bool) or not isinstance(row.get("size_bytes"), int) or
                not isinstance(row.get("filename"), str) or not isinstance(row.get("owner_username"), str) or
                not isinstance(row.get("sha256_hex"), str) or not _SHA256_RE.fullmatch(row["sha256_hex"]) or
                not isinstance(row.get("created_at"), int) or not isinstance(row.get("access"), str)):
            raise ClientError("MALFORMED_RESPONSE", "Server file listing is invalid")
    return files


def upload_file(token: str, source: Path, share_with: list[str] | None = None) -> dict:
    path = Path(source).expanduser()
    if not path.is_file():
        raise ClientError("INVALID_REQUEST", "Upload source must be a regular file")
    try:
        size_bytes = path.stat().st_size
    except OSError as exc:
        raise ClientError("INVALID_REQUEST", "Upload source is unavailable") from exc
    if size_bytes > MAX_FILE_BYTES:
        raise ClientError("FILE_TOO_LARGE", "File size exceeds the transfer limit")
    recipients = [] if share_with is None else share_with
    if not isinstance(recipients, list) or any(not isinstance(item, str) for item in recipients):
        raise ClientError("INVALID_REQUEST", "Sharing recipients are invalid")
    request = _request("upload", {"token": token, "filename": path.name,
                                   "size_bytes": size_bytes, "share_with": recipients})
    try:
        with path.open("rb") as source_stream:
            return upload_binary(request, source_stream, size_bytes)
    except ClientError:
        raise
    except OSError as exc:
        raise ClientError("INVALID_REQUEST", "Upload source is unavailable") from exc


def download_file(token: str, file_id: int, destination: Path) -> dict:
    request = _request("download", {"token": token, "file_id": file_id})
    return download_binary(request, Path(destination))


def delete_file(token: str, file_id: int) -> None:
    _expect_empty(request_control(_request("delete", {"token": token, "file_id": file_id})))


def grant_file_access(token: str, file_id: int, username: str) -> None:
    _expect_empty(request_control(_request("share.grant", {
        "token": token, "file_id": file_id, "username": username,
    })))


def revoke_file_access(token: str, file_id: int, username: str) -> None:
    _expect_empty(request_control(_request("share.revoke", {
        "token": token, "file_id": file_id, "username": username,
    })))


def admin_create_user(token: str, username: str, password: str, role: str) -> int:
    data = request_control(_request("admin.create_user", {
        "token": token, "username": username, "password": password, "role": role,
    }))
    user_id = data.get("user_id")
    if set(data) != {"user_id"} or isinstance(user_id, bool) or not isinstance(user_id, int) or user_id <= 0:
        raise ClientError("MALFORMED_RESPONSE", "Server user-creation response is invalid")
    return user_id


def admin_set_user_role(token: str, user_id: int, role: str) -> None:
    _expect_empty(request_control(_request("admin.set_user_role", {
        "token": token, "user_id": user_id, "role": role,
    })))


def admin_set_user_active(token: str, user_id: int, is_active: bool) -> None:
    _expect_empty(request_control(_request("admin.set_user_active", {
        "token": token, "user_id": user_id, "is_active": is_active,
    })))
