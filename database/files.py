"""File metadata and ACL persistence functions."""

import sqlite3

from database.core import execute
from database.errors import DatabaseError


def create_file(
    conn: sqlite3.Connection,
    owner_user_id: int,
    storage_id: str,
    filename: str,
    size_bytes: int,
    sha256_digest: bytes,
    created_at: int,
) -> int:
    cursor = execute(
        conn,
        """INSERT INTO files(
               owner_user_id, storage_id, filename, size_bytes, sha256_digest, created_at
           ) VALUES (?, ?, ?, ?, ?, ?)""",
        (owner_user_id, storage_id, filename, size_bytes, sha256_digest, created_at),
    )
    if cursor.lastrowid is None:
        raise DatabaseError("File metadata could not be created")
    return int(cursor.lastrowid)


def get_file(conn: sqlite3.Connection, file_id: int) -> dict | None:
    row = execute(
        conn,
        """SELECT f.*, u.username AS owner_username
           FROM files AS f JOIN users AS u ON u.user_id = f.owner_user_id
           WHERE f.file_id = ?""",
        (file_id,),
    ).fetchone()
    return dict(row) if row is not None else None


def list_accessible_files(
    conn: sqlite3.Connection,
    user_id: int,
    role: str,
) -> list[dict]:
    if role not in {"Admin", "User"}:
        raise DatabaseError("Invalid role")
    if role == "Admin":
        rows = execute(
            conn,
            """SELECT f.file_id, f.filename, u.username AS owner_username,
                      f.size_bytes, f.sha256_digest, f.created_at,
                      CASE WHEN f.owner_user_id = ? THEN 'owner' ELSE 'admin' END AS access
               FROM files AS f JOIN users AS u ON u.user_id = f.owner_user_id
               ORDER BY f.created_at DESC, f.file_id DESC""",
            (user_id,),
        ).fetchall()
    else:
        rows = execute(
            conn,
            """SELECT f.file_id, f.filename, u.username AS owner_username,
                      f.size_bytes, f.sha256_digest, f.created_at,
                      CASE WHEN f.owner_user_id = ? THEN 'owner' ELSE 'shared' END AS access
               FROM files AS f JOIN users AS u ON u.user_id = f.owner_user_id
               WHERE f.owner_user_id = ?
                  OR EXISTS (
                      SELECT 1 FROM file_acl AS acl
                      WHERE acl.file_id = f.file_id AND acl.user_id = ?
                  )
               ORDER BY f.created_at DESC, f.file_id DESC""",
            (user_id, user_id, user_id),
        ).fetchall()
    return [dict(row) for row in rows]


def grant_access(
    conn: sqlite3.Connection,
    file_id: int,
    user_id: int,
    granted_by: int,
    created_at: int,
) -> None:
    execute(
        conn,
        "INSERT INTO file_acl(file_id, user_id, granted_by, created_at) "
        "VALUES (?, ?, ?, ?)",
        (file_id, user_id, granted_by, created_at),
    )


def revoke_access(conn: sqlite3.Connection, file_id: int, user_id: int) -> None:
    execute(
        conn,
        "DELETE FROM file_acl WHERE file_id = ? AND user_id = ?",
        (file_id, user_id),
    )


def list_file_grants(conn: sqlite3.Connection, file_id: int) -> list[dict]:
    rows = execute(
        conn,
        """SELECT acl.file_id, acl.user_id, u.username,
                  acl.granted_by, grantor.username AS granted_by_username,
                  acl.created_at
           FROM file_acl AS acl
           JOIN users AS u ON u.user_id = acl.user_id
           JOIN users AS grantor ON grantor.user_id = acl.granted_by
           WHERE acl.file_id = ? ORDER BY u.username COLLATE NOCASE""",
        (file_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def delete_file(conn: sqlite3.Connection, file_id: int) -> None:
    execute(conn, "DELETE FROM files WHERE file_id = ?", (file_id,))


def list_storage_ids(conn: sqlite3.Connection) -> set[str]:
    rows = execute(conn, "SELECT storage_id FROM files").fetchall()
    return {str(row["storage_id"]) for row in rows}
