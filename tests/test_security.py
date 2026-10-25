"""Focused tests for security primitives."""

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security.authorization import authorize
from security.encryption import decrypt_file, encrypt_file, load_encryption_key
from security.errors import AuthorizationError, EncryptionError, PasswordError, SessionError
from security.integrity import sha256_digest, sha256_hex, verify_sha256
from security.key_store import create_encryption_key_file
from security.passwords import hash_password, verify_password
from security.sessions import generate_token, token_digest, validate_session

_WORKSPACE_PARENT = Path(__file__).resolve().parents[2]
_STORAGE_ID = "a" * 32


class PasswordTests(unittest.TestCase):
    def test_hash_and_verify(self):
        password = "correct horse battery"
        password_hash = hash_password(password)
        self.assertTrue(password_hash.startswith(b"$2b$12$"))
        self.assertTrue(verify_password(password, password_hash))
        self.assertFalse(verify_password("different secure pass", password_hash))
        self.assertNotEqual(password_hash, hash_password(password))

    def test_password_byte_limits_and_bad_types(self):
        for password in ("short", "é" * 37, "valid length \ud800", None, object()):
            with self.subTest(password=password):
                with self.assertRaises(PasswordError):
                    hash_password(password)
        # 12 UTF-8 bytes is valid; 72 bytes is valid.
        self.assertTrue(verify_password("é" * 6, hash_password("é" * 6)))
        self.assertTrue(verify_password("a" * 72, hash_password("a" * 72)))

    def test_malformed_bcrypt_hash_fails_closed(self):
        self.assertFalse(verify_password("valid length password", b"not-a-bcrypt-hash"))
        self.assertFalse(verify_password("valid length password", "not bytes"))


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.token = generate_token()
        self.record = {
            "token_hash": token_digest(self.token), "user_id": 7,
            "created_at": 100, "expires_at": 200, "revoked_at": None,
            "username": "alice", "role": "User", "is_active": 1,
        }

    def test_generated_token_and_digest(self):
        token = generate_token()
        self.assertEqual(len(token), 43)
        self.assertRegex(token, r"^[A-Za-z0-9_-]{43}$")
        self.assertEqual(token_digest(token), hashlib.sha256(token.encode("ascii")).digest())
        self.assertEqual(len(token_digest(token)), 32)

    def test_valid_session_returns_only_identity(self):
        self.assertEqual(validate_session(self.token, self.record, 199), {
            "user_id": 7, "username": "alice", "role": "User",
        })

    def test_missing_mismatched_and_malformed_session(self):
        with self.assertRaises(SessionError):
            validate_session(self.token, None, 150)
        with self.assertRaises(SessionError):
            validate_session(generate_token(), self.record, 150)
        for token in ("", "x" * 43, "not-a-token"):
            with self.subTest(token=token):
                with self.assertRaises(SessionError):
                    token_digest(token)

    def test_expiry_boundary_revocation_and_account_state(self):
        with self.assertRaisesRegex(SessionError, "Session has expired") as raised:
            validate_session(self.token, self.record, 200)
        self.assertEqual(raised.exception.code, "SESSION_EXPIRED")
        revoked = {**self.record, "revoked_at": 150}
        with self.assertRaisesRegex(SessionError, "revoked"):
            validate_session(self.token, revoked, 160)
        inactive = {**self.record, "is_active": 0}
        with self.assertRaisesRegex(SessionError, "inactive"):
            validate_session(self.token, inactive, 160)
        with self.assertRaises(SessionError):
            validate_session(self.token, self.record, 99)
        with self.assertRaises(SessionError):
            validate_session(self.token, self.record, True)

    def test_invalid_record_fields(self):
        for changes in ({"expires_at": 100}, {"user_id": 0}, {"role": "Root"},
                        {"role": []}, {"username": ""}, {"is_active": 1.0}):
            with self.subTest(changes=changes), self.assertRaises(SessionError):
                validate_session(self.token, {**self.record, **changes}, 150)


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.owner = {"user_id": 7, "role": "User", "is_active": 1}
        self.other = {"user_id": 8, "role": "User", "is_active": 1}
        self.file = {"owner_user_id": 7, "grantee_user_ids": {8}}

    def test_user_capabilities_and_sharing(self):
        for action in ("list_files", "upload", "logout"):
            authorize(self.owner, action)
        for action in ("download", "delete", "share.grant", "share.revoke"):
            authorize(self.owner, action, self.file)
        authorize(self.other, "download", self.file)
        for action in ("delete", "share.grant", "share.revoke"):
            with self.subTest(action=action), self.assertRaises(AuthorizationError):
                authorize(self.other, action, self.file)

    def test_admin_and_denials(self):
        admin = {"user_id": 1, "role": "Admin", "is_active": 1}
        authorize(admin, "admin.create_user")
        authorize(admin, "delete")
        for user, action, file_record in (
            (self.owner, "admin.create_user", None),
            (self.owner, "unknown", None),
            (self.owner, [], None),
            ({"user_id": 7, "role": [], "is_active": 1}, "upload", None),
            ({"user_id": 0, "role": "User", "is_active": 1}, "upload", None),
            ({**self.owner, "is_active": 0}, "upload", None),
            (self.other, "download", {"owner_user_id": 7}),
        ):
            with self.subTest(action=action), self.assertRaises(AuthorizationError):
                authorize(user, action, file_record)


class EncryptionTests(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(32))

    def test_round_trip_and_fresh_12_byte_nonces(self):
        nonces = [b"a" * 12, b"b" * 12]
        with patch("security.encryption.os.urandom", side_effect=nonces) as random_bytes:
            first = encrypt_file(b"secret payload", _STORAGE_ID, self.key)
            second = encrypt_file(b"secret payload", _STORAGE_ID, self.key)
        self.assertEqual(random_bytes.call_args_list[0].args, (12,))
        self.assertEqual(random_bytes.call_args_list[1].args, (12,))
        self.assertNotEqual(first[5:17], second[5:17])
        self.assertEqual(decrypt_file(first, _STORAGE_ID, self.key), b"secret payload")
        self.assertEqual(decrypt_file(encrypt_file(b"", _STORAGE_ID, self.key), _STORAGE_ID, self.key), b"")

    def test_tampering_wrong_key_and_malformed_payload(self):
        encrypted = encrypt_file(b"secret payload", _STORAGE_ID, self.key)
        changed = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
        for payload, storage_id, key in (
            (changed, _STORAGE_ID, self.key),
            (encrypted, "b" * 32, self.key),
            (b"bad", _STORAGE_ID, self.key),
            (b"other" + encrypted[5:], _STORAGE_ID, self.key),
            (encrypted, _STORAGE_ID, b"x" * 16),
        ):
            with self.subTest(payload=payload[:5], storage_id=storage_id), self.assertRaises(EncryptionError):
                decrypt_file(payload, storage_id, key)

    def test_bad_inputs_to_encrypt(self):
        with self.assertRaises(EncryptionError):
            encrypt_file(b"data", "../path", self.key)
        with self.assertRaises(EncryptionError):
            encrypt_file(b"data", _STORAGE_ID, b"short")


class IntegrityTests(unittest.TestCase):
    def test_digest_and_verification(self):
        digest = sha256_digest(b"contents")
        self.assertEqual(len(digest), 32)
        self.assertEqual(sha256_hex(b"contents"), digest.hex())
        self.assertTrue(verify_sha256(b"contents", digest))
        self.assertFalse(verify_sha256(b"changed", digest))
        self.assertFalse(verify_sha256(b"contents", b"short"))
        with self.assertRaises(TypeError):
            sha256_digest("not bytes")


class KeyStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=_WORKSPACE_PARENT)
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "private" / "file.key"

    def test_create_and_load_key(self):
        create_encryption_key_file(self.path)
        key = load_encryption_key(self.path)
        self.assertEqual(len(key), 32)
        self.assertEqual(self.path.stat().st_size, 32)

    def test_refuses_overwrite_and_missing_or_invalid_key(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_bytes(b"existing-value")
        with self.assertRaises(EncryptionError) as raised:
            create_encryption_key_file(self.path)
        self.assertEqual(raised.exception.code, "KEY_ALREADY_EXISTS")
        self.assertEqual(self.path.read_bytes(), b"existing-value")
        with self.assertRaises(EncryptionError):
            load_encryption_key(self.path)
        with self.assertRaises(EncryptionError):
            load_encryption_key(self.path.with_name("missing.key"))

    def test_rejects_key_path_inside_repository(self):
        repo_key_path = Path(__file__).resolve().parents[1] / "must-not-create.key"
        with self.assertRaises(EncryptionError):
            create_encryption_key_file(repo_key_path)
        self.assertFalse(repo_key_path.exists())


if __name__ == "__main__":
    unittest.main()
