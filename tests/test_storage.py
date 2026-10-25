"""Tests for local encrypted object storage and startup initialization."""

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from server.errors import StorageError
from server.storage import (cleanup_orphans, initialize_storage, new_storage_id,
                            read_encrypted, remove_storage_object, write_encrypted)

_WORKSPACE_PARENT = Path(__file__).resolve().parents[2]


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=_WORKSPACE_PARENT)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "storage"
        initialize_storage(self.root)

    def test_initialize_and_write_read_remove(self):
        storage_id = new_storage_id()
        self.assertRegex(storage_id, r"^[0-9a-f]{32}$")
        write_encrypted(self.root, storage_id, b"ciphertext")
        self.assertEqual(read_encrypted(self.root, storage_id), b"ciphertext")
        remove_storage_object(self.root, storage_id)
        with self.assertRaises(StorageError):
            read_encrypted(self.root, storage_id)
        remove_storage_object(self.root, storage_id)  # idempotent

    def test_rejects_paths_inside_repository_and_invalid_storage_ids(self):
        with self.assertRaises(StorageError):
            initialize_storage(Path(__file__).resolve().parents[1] / "unsafe-storage")
        for bad_id in ("../outside", "A" * 32, "x", ""):
            with self.subTest(bad_id=bad_id), self.assertRaises(StorageError):
                read_encrypted(self.root, bad_id)
        with self.assertRaises(StorageError):
            write_encrypted(self.root, "a" * 32, "not bytes")

    def test_write_does_not_overwrite_existing_object(self):
        storage_id = new_storage_id()
        write_encrypted(self.root, storage_id, b"original")
        with self.assertRaises(StorageError):
            write_encrypted(self.root, storage_id, b"replacement")
        self.assertEqual(read_encrypted(self.root, storage_id), b"original")

    def test_failed_publish_removes_temporary_file(self):
        with patch("server.storage.os.rename", side_effect=OSError("simulated failure")):
            with self.assertRaises(StorageError):
                write_encrypted(self.root, new_storage_id(), b"ciphertext")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_cleanup_only_removes_old_orphans_and_old_temporary_files(self):
        referenced = new_storage_id()
        orphan = new_storage_id()
        recent = new_storage_id()
        old_temp = self.root / ".zts-upload-old.tmp"
        write_encrypted(self.root, referenced, b"keep")
        write_encrypted(self.root, orphan, b"remove")
        write_encrypted(self.root, recent, b"keep recent")
        old_temp.write_bytes(b"partial")
        old_time = time.time() - 7200
        os.utime(self.root / orphan, (old_time, old_time))
        os.utime(old_temp, (old_time, old_time))
        self.assertEqual(cleanup_orphans(self.root, {referenced, recent}, int(time.time() - 3600)), 2)
        self.assertTrue((self.root / referenced).exists())
        self.assertTrue((self.root / recent).exists())
        self.assertFalse((self.root / orphan).exists())
        self.assertFalse(old_temp.exists())


if __name__ == "__main__":
    unittest.main()
