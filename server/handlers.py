"""Validate and dispatch one authenticated application request per TLS socket."""

from __future__ import annotations

import io
import json
import logging
import re
import time
import unicodedata
import uuid

from database.audit import log_event
from database.core import transaction
from database.files import (
    create_file, delete_file, get_file, grant_access, list_accessible_files,
    list_file_grants, revoke_access,
)
from database.sessions import create_session, get_session, revoke_session, revoke_user_sessions
from database.users import (
    create_user, get_user_by_id, get_user_by_username, set_user_active,
    set_user_role,
)
from database.errors import DatabaseError
from security.authorization import authorize
from security.encryption import decrypt_file, encrypt_file
from security.errors import AuthorizationError, EncryptionError, PasswordError, SessionError
from security.integrity import sha256_digest, verify_sha256
from security.passwords import hash_password, verify_password
from security.sessions import generate_token, token_digest, validate_session
from server.config import ServerConfig
from server.errors import ProtocolError, RequestError, StorageError
from server.protocol import MAX_FILE_BYTES, recv_binary, send_binary, send_control
from server.storage import new_storage_id, read_encrypted, remove_storage_object, write_encrypted

_ACTIONS = {
    "login", "logout", "list_files", "upload", "download", "delete",
    "share.grant", "share.revoke", "admin.create_user", "admin.set_user_role",
    "admin.set_user_active",
}
_REQUEST_KEYS = {"version", "request_id", "action", "payload"}
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_LOGGER = logging.getLogger(__name__)


def _error(code: str, message: str, request_id: str | None) -> dict:
    return {"version": 1, "request_id": request_id, "ok": False,
            "error": {"code": code, "message": message}}


def _success(request_id: str, data: dict) -> dict:
    return {"version": 1, "request_id": request_id, "ok": True, "data": data}


def _validate_envelope(request: object) -> tuple[str, str, dict]:
    if not isinstance(request, dict) or set(request) != _REQUEST_KEYS:
        raise RequestError("INVALID_REQUEST", "Request envelope is invalid")
    if type(request["version"]) is not int or request["version"] != 1:
        raise RequestError("UNSUPPORTED_VERSION", "Protocol version is not supported")
    request_id = request["request_id"]
    if not isinstance(request_id, str):
        raise RequestError("INVALID_REQUEST", "Request identifier is invalid")
    try:
        parsed_id = uuid.UUID(request_id)
    except (ValueError, AttributeError) as exc:
        raise RequestError("INVALID_REQUEST", "Request identifier is invalid") from exc
    if parsed_id.version != 4 or str(parsed_id) != request_id.lower():
        raise RequestError("INVALID_REQUEST", "Request identifier must be UUIDv4")
    action, payload = request["action"], request["payload"]
    if not isinstance(action, str) or action not in _ACTIONS or not isinstance(payload, dict):
        raise RequestError("INVALID_REQUEST", "Action or payload is invalid")
    return request_id, action, payload


def _exact_payload(payload: dict, expected: set[str]) -> None:
    if set(payload) != expected:
        raise RequestError("INVALID_REQUEST", "Action payload fields are invalid")


def _string(value: object, name: str, min_length: int = 1, max_length: int = 255) -> str:
    if not isinstance(value, str) or not min_length <= len(value) <= max_length:
        raise RequestError("INVALID_REQUEST", f"{name} is invalid")
    return value


def _file_id(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RequestError("INVALID_REQUEST", "File identifier is invalid")
    return value


def _user_id(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RequestError("INVALID_REQUEST", "User identifier is invalid")
    return value


def _filename(value: object) -> str:
    name = _string(value, "Filename", 1, 255)
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise RequestError("INVALID_FILENAME", "Filename is invalid") from exc
    if (not 1 <= len(encoded) <= 255 or name != unicodedata.normalize("NFC", name) or
            name in {".", ".."} or any(ch in name for ch in ("/", "\\", "\x00")) or
            any(unicodedata.category(ch) == "Cc" for ch in name)):
        raise RequestError("INVALID_FILENAME", "Filename is invalid")
    return name


def _token(payload: dict) -> str:
    value = payload.get("token")
    if not isinstance(value, str) or not _TOKEN_RE.fullmatch(value):
        raise RequestError("AUTH_REQUIRED", "Authentication is required")
    return value


def _identity(token: str) -> dict:
    try:
        digest = token_digest(token)
        with transaction() as conn:
            record = get_session(conn, digest)
        return validate_session(token, record, int(time.time()))
    except SessionError as exc:
        if exc.code == "SESSION_EXPIRED":
            raise RequestError("SESSION_EXPIRED", "Session has expired") from exc
        raise RequestError("AUTH_REQUIRED", "Authentication is required") from exc
    except DatabaseError as exc:
        raise RequestError("DATABASE_ERROR", "Database operation failed") from exc


def _authorized_file(user: dict, action: str, file_id: int) -> dict:
    try:
        with transaction() as conn:
            record = get_file(conn, file_id)
            if record is None:
                raise RequestError("NOT_FOUND", "File was not found")
            grants = list_file_grants(conn, file_id)
        policy_record = {**record, "grantee_user_ids": {row["user_id"] for row in grants}}
        authorize({**user, "is_active": 1}, action, policy_record)
        return record
    except AuthorizationError as exc:
        # Do not disclose whether another user's file exists.
        raise RequestError("NOT_FOUND", "File was not found") from exc
    except DatabaseError as exc:
        raise RequestError("DATABASE_ERROR", "Database operation failed") from exc


def _audit(actor_id: int | None, action: str, file_id: int | None, outcome: str, detail: dict | None = None) -> None:
    try:
        with transaction() as conn:
            log_event(conn, actor_id, action, file_id, outcome,
                      json.dumps(detail or {}, separators=(",", ":"), ensure_ascii=False), int(time.time()))
    except DatabaseError as exc:
        raise RequestError("DATABASE_ERROR", "Database operation failed") from exc


def _send_error(conn, error: RequestError | ProtocolError, request_id: str | None) -> None:
    code = error.code
    message = error.message
    try:
        send_control(conn, _error(code, message, request_id))
    except ProtocolError:
        # The caller closes the one-operation connection; there is no safe retry.
        pass


def _send_success(conn, request_id: str, data: dict) -> bool:
    try:
        send_control(conn, _success(request_id, data))
        return True
    except ProtocolError:
        # A partial control write cannot be repaired with a second frame.
        return False


def _dispatch(
    request_id: str,
    action: str,
    payload: dict,
    conn,
    config: ServerConfig,
    encryption_key: bytes,
) -> None:
    if action == "login":
        _login(request_id, payload, conn)
        return
    if action == "upload":
        _upload(request_id, payload, conn, config, encryption_key)
        return
    if action == "download":
        _download(request_id, payload, conn, config, encryption_key)
        return
    data = _execute_control(action, payload, config)
    _send_success(conn, request_id, data)


def _login(request_id: str, payload: dict, conn) -> None:
    _exact_payload(payload, {"username", "password"})
    username = _string(payload["username"], "Username", 1, 64)
    password = payload["password"]
    if not isinstance(password, str):
        raise RequestError("INVALID_CREDENTIALS", "Username or password is invalid")
    try:
        with transaction() as db:
            user = get_user_by_username(db, username)
        if user is None or not user["is_active"] or not verify_password(password, user["password_hash"]):
            _audit(None, "login", None, "denied", {"username": username[:64]})
            raise RequestError("INVALID_CREDENTIALS", "Username or password is invalid")
        token = generate_token()
        now_epoch = int(time.time())
        expires_at = now_epoch + 8 * 60 * 60
        with transaction() as db:
            create_session(db, token_digest(token), user["user_id"], now_epoch, expires_at)
            log_event(db, user["user_id"], "login", None, "success", "{}", now_epoch)
        _send_success(conn, request_id, {
            "token": token, "expires_at": expires_at,
            "user": {"user_id": user["user_id"], "username": user["username"], "role": user["role"]},
        })
    except PasswordError as exc:
        raise RequestError("INVALID_CREDENTIALS", "Username or password is invalid") from exc
    except DatabaseError as exc:
        raise RequestError("DATABASE_ERROR", "Database operation failed") from exc


def _execute_control(action: str, payload: dict, config: ServerConfig) -> dict:
    required = {
        "logout": {"token"}, "list_files": {"token"}, "delete": {"token", "file_id"},
        "share.grant": {"token", "file_id", "username"},
        "share.revoke": {"token", "file_id", "username"},
        "admin.create_user": {"token", "username", "password", "role"},
        "admin.set_user_role": {"token", "user_id", "role"},
        "admin.set_user_active": {"token", "user_id", "is_active"},
    }[action]
    _exact_payload(payload, required)
    token = _token(payload)
    user = _identity(token)
    if action not in {"delete", "share.grant", "share.revoke"}:
        authorize({**user, "is_active": 1}, action)
    now = int(time.time())
    if action == "logout":
        digest = token_digest(token)
        with transaction() as conn:
            revoke_session(conn, digest, now)
            log_event(conn, user["user_id"], "logout", None, "success", "{}", now)
        return {}
    if action == "list_files":
        with transaction() as conn:
            records = list_accessible_files(conn, user["user_id"], user["role"])
        files = [{"file_id": row["file_id"], "filename": row["filename"],
                  "owner_username": row["owner_username"], "size_bytes": row["size_bytes"],
                  "sha256_hex": row["sha256_digest"].hex(), "created_at": row["created_at"],
                  "access": row["access"]} for row in records]
        return {"files": files}
    if action == "delete":
        file_id = _file_id(payload["file_id"])
        record = _authorized_file(user, action, file_id)
        with transaction() as conn:
            log_event(conn, user["user_id"], "file.delete", file_id, "success", "{}", now)
            delete_file(conn, file_id)
        try:
            remove_storage_object(config.storage_dir, record["storage_id"])
        except StorageError:
            # DB metadata is already gone; cleanup can remove the resulting orphan.
            _LOGGER.warning("Deleted file object removal failed; orphan cleanup will retry")
        return {}
    if action.startswith("share."):
        file_id = _file_id(payload["file_id"])
        record = _authorized_file(user, action, file_id)
        username = _string(payload["username"], "Username", 1, 64)
        with transaction() as conn:
            target = get_user_by_username(conn, username)
            if target is None or not target["is_active"]:
                raise RequestError("NOT_FOUND", "User was not found")
            if action == "share.grant":
                grant_access(conn, file_id, target["user_id"], user["user_id"], now)
                log_event(conn, user["user_id"], "file.share_grant", file_id, "success",
                          json.dumps({"username": target["username"]}, separators=(",", ":")), now)
            else:
                revoke_access(conn, file_id, target["user_id"])
                log_event(conn, user["user_id"], "file.share_revoke", file_id, "success",
                          json.dumps({"username": target["username"]}, separators=(",", ":")), now)
        return {}
    if action == "admin.create_user":
        username = _string(payload["username"], "Username", 1, 64)
        password = payload["password"]
        role = payload["role"]
        if not isinstance(password, str) or not isinstance(role, str) or role not in {"Admin", "User"}:
            raise RequestError("INVALID_REQUEST", "User details are invalid")
        try:
            hashed = hash_password(password)
        except PasswordError as exc:
            raise RequestError("INVALID_REQUEST", "Password must contain 12 to 72 UTF-8 bytes") from exc
        try:
            with transaction() as conn:
                user_id = create_user(conn, username, hashed, role, now)
                log_event(conn, user["user_id"], "user.create", None, "success",
                          json.dumps({"username": username, "role": role}, separators=(",", ":")), now)
        except DatabaseError as exc:
            raise RequestError("CONFLICT", "User could not be created") from exc
        return {"user_id": user_id}
    if action == "admin.set_user_role":
        user_id = _user_id(payload["user_id"])
        role = payload["role"]
        if not isinstance(role, str) or role not in {"Admin", "User"}:
            raise RequestError("INVALID_REQUEST", "Role is invalid")
        with transaction() as conn:
            if get_user_by_id(conn, user_id) is None:
                raise RequestError("NOT_FOUND", "User was not found")
            set_user_role(conn, user_id, role)
            log_event(conn, user["user_id"], "user.role_change", None, "success",
                      json.dumps({"user_id": user_id, "role": role}, separators=(",", ":")), now)
        return {}
    if action == "admin.set_user_active":
        user_id = _user_id(payload["user_id"])
        is_active = payload["is_active"]
        if type(is_active) is not bool:
            raise RequestError("INVALID_REQUEST", "Account state is invalid")
        with transaction() as conn:
            if get_user_by_id(conn, user_id) is None:
                raise RequestError("NOT_FOUND", "User was not found")
            set_user_active(conn, user_id, is_active)
            if not is_active:
                revoke_user_sessions(conn, user_id, now)
            event = "user.activate" if is_active else "user.deactivate"
            log_event(conn, user["user_id"], event, None, "success",
                      json.dumps({"user_id": user_id}, separators=(",", ":")), now)
        return {}
    raise RequestError("INVALID_REQUEST", "Action is not supported")


def _upload(request_id: str, payload: dict, conn, config: ServerConfig, encryption_key: bytes) -> None:
    _exact_payload(payload, {"token", "filename", "size_bytes", "share_with"})
    token = _token(payload)
    user = _identity(token)
    authorize({**user, "is_active": 1}, "upload")
    filename = _filename(payload["filename"])
    size = payload["size_bytes"]
    if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= MAX_FILE_BYTES:
        raise RequestError("FILE_TOO_LARGE", "File size exceeds the transfer limit")
    recipients = payload["share_with"]
    if not isinstance(recipients, list) or len(recipients) > 100 or any(not isinstance(name, str) for name in recipients):
        raise RequestError("INVALID_REQUEST", "Sharing recipients are invalid")
    if len({name.casefold() for name in recipients}) != len(recipients):
        raise RequestError("INVALID_REQUEST", "Sharing recipients must be distinct")
    now = int(time.time())
    try:
        with transaction() as db:
            targets = []
            for name in recipients:
                target = get_user_by_username(db, name)
                if target is None or not target["is_active"]:
                    raise RequestError("NOT_FOUND", "Sharing recipient was not found")
                targets.append(target)
    except DatabaseError as exc:
        raise RequestError("DATABASE_ERROR", "Database operation failed") from exc
    if not _send_success(conn, request_id, {"ready": True}):
        return
    storage_id: str | None = None
    committed = False
    try:
        plaintext = recv_binary(conn, size)
        digest = sha256_digest(plaintext)
        storage_id = new_storage_id()
        encrypted = encrypt_file(plaintext, storage_id, encryption_key)
        write_encrypted(config.storage_dir, storage_id, encrypted)
        with transaction() as db:
            file_id = create_file(db, user["user_id"], storage_id, filename, size, digest, now)
            for target in targets:
                grant_access(db, file_id, target["user_id"], user["user_id"], now)
            log_event(db, user["user_id"], "file.upload", file_id, "success",
                      json.dumps({"filename": filename, "size_bytes": size,
                                  "shared_with": [row["username"] for row in targets]},
                                 separators=(",", ":"), ensure_ascii=False), now)
        committed = True
        send_control(conn, _success(request_id, {"file_id": file_id, "sha256_hex": digest.hex()}))
    except (ProtocolError, RequestError, DatabaseError, StorageError, EncryptionError) as exc:
        if committed:
            # A lost final reply cannot undo committed metadata or its ciphertext.
            return
        if storage_id is not None:
            try:
                remove_storage_object(config.storage_dir, storage_id)
            except StorageError:
                pass
        code = exc.code if isinstance(exc, (ProtocolError, RequestError)) else (
            "STORAGE_ERROR" if isinstance(exc, StorageError) else
            "INTEGRITY_FAILURE" if isinstance(exc, EncryptionError) else "DATABASE_ERROR")
        safe_message = exc.message if isinstance(exc, (ProtocolError, RequestError, StorageError)) else "Upload could not be completed"
        try:
            _audit(user["user_id"], "file.upload", None, "failure", {"code": code})
        except RequestError:
            pass
        _send_error(conn, RequestError(code, safe_message), request_id)
    except Exception:
        if committed:
            return
        if storage_id is not None:
            try:
                remove_storage_object(config.storage_dir, storage_id)
            except StorageError:
                pass
        try:
            _audit(user["user_id"], "file.upload", None, "failure", {"code": "INTERNAL_ERROR"})
        except RequestError:
            pass
        _send_error(conn, RequestError("INTERNAL_ERROR", "Upload could not be completed"), request_id)


def _download(request_id: str, payload: dict, conn, config: ServerConfig, encryption_key: bytes) -> None:
    _exact_payload(payload, {"token", "file_id"})
    user = _identity(_token(payload))
    file_id = _file_id(payload["file_id"])
    record = _authorized_file(user, "download", file_id)
    try:
        ciphertext = read_encrypted(config.storage_dir, record["storage_id"])
        plaintext = decrypt_file(ciphertext, record["storage_id"], encryption_key)
        if len(plaintext) != record["size_bytes"] or not verify_sha256(plaintext, record["sha256_digest"]):
            raise RequestError("INTEGRITY_FAILURE", "Stored file failed integrity verification")
    except StorageError as exc:
        raise RequestError("STORAGE_ERROR", "Stored file is unavailable") from exc
    except EncryptionError as exc:
        raise RequestError("INTEGRITY_FAILURE", "Stored file failed integrity verification") from exc
    if not _send_success(conn, request_id, {
        "filename": record["filename"], "size_bytes": record["size_bytes"],
        "sha256_hex": record["sha256_digest"].hex(),
    }):
        return
    try:
        send_binary(conn, io.BytesIO(plaintext), len(plaintext))
    except ProtocolError:
        # The metadata frame is already sent; a second control response is forbidden.
        try:
            _audit(user["user_id"], "file.download", file_id, "failure", {"code": "TRANSFER_INCOMPLETE"})
        except RequestError:
            pass
        return
    try:
        _audit(user["user_id"], "file.download", file_id, "success", {"size_bytes": len(plaintext)})
    except RequestError:
        # Bytes have already been sent; a second control response would corrupt the stream.
        pass


def handle_request(
    request: dict,
    peer: tuple[str, int],
    conn,
    config: ServerConfig,
    encryption_key: bytes,
) -> None:
    """Validate, execute, and respond to one operation on an established TLS socket."""
    del peer  # peer addresses are intentionally not included in user-controlled audit detail
    request_id: str | None = None
    if isinstance(request, dict) and isinstance(request.get("request_id"), str):
        try:
            candidate = uuid.UUID(request["request_id"])
            if candidate.version == 4 and str(candidate) == request["request_id"].lower():
                request_id = request["request_id"]
        except (ValueError, AttributeError):
            pass
    try:
        request_id, action, payload = _validate_envelope(request)
        _dispatch(request_id, action, payload, conn, config, encryption_key)
    except RequestError as exc:
        _send_error(conn, exc, request_id)
    except AuthorizationError:
        _send_error(conn, RequestError("FORBIDDEN", "Access denied"), request_id)
    except DatabaseError:
        _send_error(conn, RequestError("DATABASE_ERROR", "Database operation failed"), request_id)
    except EncryptionError:
        _send_error(conn, RequestError("INTEGRITY_FAILURE", "File integrity verification failed"), request_id)
    except StorageError:
        _send_error(conn, RequestError("STORAGE_ERROR", "File storage operation failed"), request_id)
    except ProtocolError as exc:
        # Transfer handlers own their response sequence. For upload, a ready frame
        # may already have been sent and handler sends the final transfer error.
        _send_error(conn, exc, request_id)
    except Exception:
        _send_error(conn, RequestError("INTERNAL_ERROR", "Operation could not be completed"), request_id)
