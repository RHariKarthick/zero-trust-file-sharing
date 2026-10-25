"""Audit event persistence."""

import sqlite3

from database.core import execute
from database.errors import DatabaseError


ALLOWED_ACTIONS = {
    "login",
    "logout",
    "user.create",
    "user.role_change",
    "user.activate",
    "user.deactivate",
    "file.upload",
    "file.download",
    "file.delete",
    "file.share_grant",
    "file.share_revoke",
}
ALLOWED_OUTCOMES = {"success", "denied", "failure"}


def log_event(
    conn: sqlite3.Connection,
    actor_user_id: int | None,
    action: str,
    file_id: int | None,
    outcome: str,
    detail_json: str,
    created_at: int,
) -> None:
    if action not in ALLOWED_ACTIONS:
        raise DatabaseError("Invalid audit action")
    if outcome not in ALLOWED_OUTCOMES:
        raise DatabaseError("Invalid audit outcome")
    execute(
        conn,
        """INSERT INTO audit_logs(
               actor_user_id, action, file_id, outcome, detail_json, created_at
           ) VALUES (?, ?, ?, ?, ?, ?)""",
        (actor_user_id, action, file_id, outcome, detail_json, created_at),
    )
