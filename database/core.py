"""SQLite connection and transaction management for local application data."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
from typing import Iterator

from database.errors import DatabaseError


SCHEMA = (
    """CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY,
        username TEXT NOT NULL COLLATE NOCASE UNIQUE
            CHECK(length(username) BETWEEN 1 AND 64),
        password_hash BLOB NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('Admin', 'User')),
        is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
        created_at INTEGER NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS sessions (
        token_hash BLOB PRIMARY KEY CHECK(length(token_hash) = 32),
        user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL CHECK(expires_at > created_at),
        revoked_at INTEGER CHECK(revoked_at IS NULL OR revoked_at >= created_at)
    )""",
    """CREATE TABLE IF NOT EXISTS files (
        file_id INTEGER PRIMARY KEY,
        owner_user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
        storage_id TEXT NOT NULL UNIQUE CHECK(length(storage_id) = 32),
        filename TEXT NOT NULL
            CHECK(length(CAST(filename AS BLOB)) BETWEEN 1 AND 255),
        size_bytes INTEGER NOT NULL CHECK(size_bytes BETWEEN 0 AND 52428800),
        sha256_digest BLOB NOT NULL CHECK(length(sha256_digest) = 32),
        created_at INTEGER NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS file_acl (
        file_id INTEGER NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
        granted_by INTEGER NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
        created_at INTEGER NOT NULL,
        PRIMARY KEY(file_id, user_id)
    )""",
    """CREATE TABLE IF NOT EXISTS audit_logs (
        event_id INTEGER PRIMARY KEY,
        actor_user_id INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
        action TEXT NOT NULL,
        file_id INTEGER REFERENCES files(file_id) ON DELETE SET NULL,
        outcome TEXT NOT NULL CHECK(outcome IN ('success', 'denied', 'failure')),
        detail_json TEXT NOT NULL DEFAULT '{}'
            CHECK(json_valid(detail_json) AND length(detail_json) <= 4096),
        created_at INTEGER NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_sessions_user_expiry ON sessions(user_id, expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_files_owner_created ON files(owner_user_id, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_acl_user_file ON file_acl(user_id, file_id)",
    "CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_audit_actor_created ON audit_logs(actor_user_id, created_at DESC)",
)


def _database_path() -> Path:
    raw_path = os.environ.get("ZTS_DB_FILE")
    if not raw_path:
        raise DatabaseError("ZTS_DB_FILE must name a database outside the repository")

    path = Path(raw_path).expanduser().resolve()
    repository_root = Path(__file__).resolve().parents[1]
    try:
        path.relative_to(repository_root)
    except ValueError:
        return path
    raise DatabaseError("ZTS_DB_FILE must name a database outside the repository")


def _connect() -> sqlite3.Connection:
    path = _database_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection
    except (OSError, sqlite3.Error) as exc:
        raise DatabaseError("Unable to open the local database") from exc


def execute(
    conn: sqlite3.Connection,
    sql: str,
    parameters: tuple[object, ...] = (),
) -> sqlite3.Cursor:
    """Execute parameterized SQL and translate SQLite errors consistently."""
    try:
        return conn.execute(sql, parameters)
    except sqlite3.Error as exc:
        raise DatabaseError("Database operation failed") from exc


@contextmanager
def transaction() -> Iterator[sqlite3.Connection]:
    """Open an immediate transaction; commit or roll back, then always close."""
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.commit()
    except sqlite3.Error as exc:
        try:
            conn.rollback()
        finally:
            raise DatabaseError("Database transaction failed") from exc
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def initialize() -> None:
    """Create tables and indexes if absent, without changing existing rows."""
    with transaction() as conn:
        for statement in SCHEMA:
            execute(conn, statement)
