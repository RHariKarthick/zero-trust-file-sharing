"""User persistence functions."""

import sqlite3

from database.core import execute
from database.errors import DatabaseError


def _user(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None


def get_user_by_username(conn: sqlite3.Connection, username: str) -> dict | None:
    row = execute(
        conn,
        "SELECT user_id, username, password_hash, role, is_active, created_at "
        "FROM users WHERE username = ? COLLATE NOCASE",
        (username,),
    ).fetchone()
    return _user(row)


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> dict | None:
    row = execute(
        conn,
        "SELECT user_id, username, password_hash, role, is_active, created_at "
        "FROM users WHERE user_id = ?",
        (user_id,),
    ).fetchone()
    return _user(row)


def create_user(
    conn: sqlite3.Connection,
    username: str,
    password_hash: bytes,
    role: str,
    now_epoch: int,
) -> int:
    cursor = execute(
        conn,
        "INSERT INTO users(username, password_hash, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        (username, password_hash, role, now_epoch),
    )
    if cursor.lastrowid is None:
        raise DatabaseError("User could not be created")
    return int(cursor.lastrowid)


def set_user_role(conn: sqlite3.Connection, user_id: int, role: str) -> None:
    cursor = execute(conn, "UPDATE users SET role = ? WHERE user_id = ?", (role, user_id))
    if cursor.rowcount != 1:
        raise DatabaseError("User does not exist")


def set_user_active(
    conn: sqlite3.Connection,
    user_id: int,
    is_active: bool,
) -> None:
    cursor = execute(
        conn,
        "UPDATE users SET is_active = ? WHERE user_id = ?",
        (int(is_active), user_id),
    )
    if cursor.rowcount != 1:
        raise DatabaseError("User does not exist")


def list_users(conn: sqlite3.Connection) -> list[dict]:
    rows = execute(
        conn,
        "SELECT user_id, username, role, is_active, created_at "
        "FROM users ORDER BY username COLLATE NOCASE",
    ).fetchall()
    return [dict(row) for row in rows]
