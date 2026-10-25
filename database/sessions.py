"""Application session persistence; raw bearer tokens are never stored."""

import sqlite3

from database.core import execute


def create_session(
    conn: sqlite3.Connection,
    token_hash: bytes,
    user_id: int,
    created_at: int,
    expires_at: int,
) -> None:
    execute(
        conn,
        "INSERT INTO sessions(token_hash, user_id, created_at, expires_at) "
        "VALUES (?, ?, ?, ?)",
        (token_hash, user_id, created_at, expires_at),
    )


def get_session(conn: sqlite3.Connection, token_hash: bytes) -> dict | None:
    """Return session and current account fields needed by validate_session."""
    row = execute(
        conn,
        """SELECT s.token_hash, s.user_id, s.created_at, s.expires_at,
                  s.revoked_at, u.username, u.role, u.is_active
           FROM sessions AS s
           JOIN users AS u ON u.user_id = s.user_id
           WHERE s.token_hash = ?""",
        (token_hash,),
    ).fetchone()
    return dict(row) if row is not None else None


def revoke_session(
    conn: sqlite3.Connection,
    token_hash: bytes,
    revoked_at: int,
) -> None:
    execute(
        conn,
        "UPDATE sessions SET revoked_at = ? "
        "WHERE token_hash = ? AND revoked_at IS NULL",
        (revoked_at, token_hash),
    )


def revoke_user_sessions(
    conn: sqlite3.Connection,
    user_id: int,
    revoked_at: int,
) -> None:
    execute(
        conn,
        "UPDATE sessions SET revoked_at = ? "
        "WHERE user_id = ? AND revoked_at IS NULL",
        (revoked_at, user_id),
    )


def delete_expired_sessions(conn: sqlite3.Connection, now_epoch: int) -> int:
    cursor = execute(conn, "DELETE FROM sessions WHERE expires_at <= ?", (now_epoch,))
    return cursor.rowcount
