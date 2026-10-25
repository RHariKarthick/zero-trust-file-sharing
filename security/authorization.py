"""Central application authorization policy (the server remains the enforcer)."""

from typing import Any

from security.errors import AuthorizationError

_ROLES = {"Admin", "User"}
_ACTIONS = {
    "list_files", "upload", "download", "delete", "share.grant", "share.revoke",
    "logout", "admin.create_user", "admin.set_user_role", "admin.set_user_active",
}
_ADMIN_ACTIONS = {"admin.create_user", "admin.set_user_role", "admin.set_user_active"}
_OWNED_ACTIONS = {"delete", "share.grant", "share.revoke"}


def authorize(user: dict[str, Any], action: str, file_record: dict[str, Any] | None = None) -> None:
    """Raise FORBIDDEN unless the active Admin/User may perform ``action``.

    For per-file decisions ``file_record`` has ``owner_user_id`` and, for download,
    ``grantee_user_ids`` (a set/list/tuple of user IDs assembled by trusted server code).
    """
    if not isinstance(user, dict) or not isinstance(user.get("role"), str) or user["role"] not in _ROLES:
        raise AuthorizationError("FORBIDDEN", "Access denied")
    is_active = user.get("is_active", 1)
    if isinstance(is_active, bool) or not isinstance(is_active, int) or is_active != 1:
        raise AuthorizationError("FORBIDDEN", "Access denied")
    if not isinstance(action, str) or action not in _ACTIONS:
        raise AuthorizationError("FORBIDDEN", "Access denied")
    user_id = user.get("user_id")
    if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id <= 0:
        raise AuthorizationError("FORBIDDEN", "Access denied")
    if user["role"] == "Admin":
        return
    if action in _ADMIN_ACTIONS:
        raise AuthorizationError("FORBIDDEN", "Access denied")
    if action in _OWNED_ACTIONS or action == "download":
        if not isinstance(file_record, dict):
            raise AuthorizationError("FORBIDDEN", "Access denied")
        owner_id = file_record.get("owner_user_id")
        if isinstance(owner_id, bool) or not isinstance(owner_id, int) or owner_id <= 0:
            raise AuthorizationError("FORBIDDEN", "Access denied")
        if owner_id == user_id:
            return
        if action == "download":
            grantees = file_record.get("grantee_user_ids", ())
            if isinstance(grantees, (set, list, tuple)) and user_id in grantees:
                return
        raise AuthorizationError("FORBIDDEN", "Access denied")

