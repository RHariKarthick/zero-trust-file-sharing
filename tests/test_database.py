"""Interface-level tests for the SQLite persistence contract."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from database import audit, core, files, sessions, users
from database.errors import DatabaseError


class DatabaseContractTests(unittest.TestCase):
    def setUp(self) -> None:
        # The managed Windows runner's default TEMP location is not writable.
        # Keep test databases in the task's writable parent directory instead.
        self.temp_dir = tempfile.TemporaryDirectory(
            dir=Path(__file__).resolve().parents[2]
        )
        self.addCleanup(self.temp_dir.cleanup)
        self.previous_db_path = os.environ.get("ZTS_DB_FILE")
        self.addCleanup(self._restore_db_path)
        os.environ["ZTS_DB_FILE"] = str(Path(self.temp_dir.name) / "app.sqlite3")
        core.initialize()

    def _restore_db_path(self) -> None:
        if self.previous_db_path is None:
            os.environ.pop("ZTS_DB_FILE", None)
        else:
            os.environ["ZTS_DB_FILE"] = self.previous_db_path

    def _create_users(self) -> tuple[int, int]:
        with core.transaction() as conn:
            admin_id = users.create_user(conn, "Admin", b"hash-a", "Admin", 100)
            alice_id = users.create_user(conn, "Alice", b"hash-b", "User", 101)
        return admin_id, alice_id

    def test_schema_is_idempotent_and_foreign_keys_are_enabled(self) -> None:
        core.initialize()
        with core.transaction() as conn:
            self.assertEqual(conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            table_names = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
        self.assertTrue({"users", "sessions", "files", "file_acl", "audit_logs"} <= table_names)

    def test_transaction_rolls_back_all_writes_on_exception(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "rollback"):
            with core.transaction() as conn:
                users.create_user(conn, "Temp", b"hash", "User", 100)
                raise RuntimeError("rollback")
        with core.transaction() as conn:
            self.assertIsNone(users.get_user_by_username(conn, "Temp"))

    def test_user_constraints_and_case_insensitive_unique_username(self) -> None:
        self._create_users()
        with self.assertRaises(DatabaseError):
            with core.transaction() as conn:
                users.create_user(conn, "aLiCe", b"hash-c", "User", 102)
        with self.assertRaises(DatabaseError):
            with core.transaction() as conn:
                users.create_user(conn, "BadRole", b"hash", "Owner", 103)

    def test_session_lookup_includes_current_user_fields_and_revocation(self) -> None:
        _, alice_id = self._create_users()
        token_hash = b"t" * 32
        with core.transaction() as conn:
            sessions.create_session(conn, token_hash, alice_id, 100, 200)
        with core.transaction() as conn:
            record = sessions.get_session(conn, token_hash)
        self.assertEqual(record["username"], "Alice")
        self.assertEqual(record["role"], "User")
        self.assertEqual(record["is_active"], 1)
        with core.transaction() as conn:
            sessions.revoke_session(conn, token_hash, 150)
        with core.transaction() as conn:
            self.assertEqual(sessions.get_session(conn, token_hash)["revoked_at"], 150)

    def test_file_acl_listing_revocation_and_delete_cascade(self) -> None:
        admin_id, alice_id = self._create_users()
        with core.transaction() as conn:
            bob_id = users.create_user(conn, "Bob", b"hash-c", "User", 102)
            file_id = files.create_file(
                conn, alice_id, "a" * 32, "report.txt", 4, b"d" * 32, 110
            )
            files.grant_access(conn, file_id, bob_id, alice_id, 111)
        with core.transaction() as conn:
            listed = files.list_accessible_files(conn, bob_id, "User")
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["access"], "shared")
        with core.transaction() as conn:
            files.revoke_access(conn, file_id, bob_id)
        with core.transaction() as conn:
            self.assertEqual(files.list_accessible_files(conn, bob_id, "User"), [])
            files.grant_access(conn, file_id, bob_id, alice_id, 112)
            files.delete_file(conn, file_id)
            self.assertEqual(files.list_file_grants(conn, file_id), [])
            self.assertEqual(files.list_storage_ids(conn), set())
            self.assertEqual(files.list_accessible_files(conn, admin_id, "Admin"), [])

    def test_file_digest_and_size_constraints(self) -> None:
        _, alice_id = self._create_users()
        with self.assertRaises(DatabaseError):
            with core.transaction() as conn:
                files.create_file(conn, alice_id, "b" * 32, "x", 1, b"short", 1)
        with self.assertRaises(DatabaseError):
            with core.transaction() as conn:
                files.create_file(conn, alice_id, "c" * 32, "x", 52_428_801, b"d" * 32, 1)

    def test_audit_action_validation_and_file_delete_retention(self) -> None:
        _, alice_id = self._create_users()
        with core.transaction() as conn:
            file_id = files.create_file(
                conn, alice_id, "d" * 32, "x", 1, b"e" * 32, 120
            )
            audit.log_event(conn, alice_id, "file.upload", file_id, "success", "{}", 121)
            files.delete_file(conn, file_id)
            event = conn.execute("SELECT file_id, action FROM audit_logs").fetchone()
            self.assertIsNone(event["file_id"])
            self.assertEqual(event["action"], "file.upload")
        with self.assertRaises(DatabaseError):
            with core.transaction() as conn:
                audit.log_event(conn, alice_id, "password.logged", None, "success", "{}", 122)

    def test_database_path_inside_repository_is_rejected(self) -> None:
        os.environ["ZTS_DB_FILE"] = str(Path(core.__file__).resolve().parents[1] / "unsafe.sqlite3")
        with self.assertRaises(DatabaseError):
            with core.transaction():
                pass


if __name__ == "__main__":
    unittest.main()
