"""Interactive, one-time creation of the initial Admin account."""

from __future__ import annotations

import getpass
import json
import time

from database.audit import log_event
from database.core import transaction
from database.users import create_user, list_users
from security.errors import PasswordError
from security.passwords import hash_password
from server.errors import ConfigurationError


def create_first_admin() -> int | None:
    """Prompt only on an empty DB; atomically create and audit the first Admin."""
    with transaction() as conn:
        if list_users(conn):
            return None

    username = input("First Admin username: ").strip()
    if not 1 <= len(username) <= 64:
        raise ConfigurationError("First Admin username must contain 1 to 64 characters")
    password = getpass.getpass("First Admin password: ")
    confirmation = getpass.getpass("Confirm First Admin password: ")
    if password != confirmation:
        raise ConfigurationError("First Admin passwords do not match")
    try:
        password_hash = hash_password(password)
    except PasswordError as exc:
        raise ConfigurationError("First Admin password must contain 12 to 72 UTF-8 bytes") from exc

    now_epoch = int(time.time())
    with transaction() as conn:
        # BEGIN IMMEDIATE prevents two concurrent first-run processes from
        # creating separate initial accounts after their interactive prompts.
        if list_users(conn):
            return None
        user_id = create_user(conn, username, password_hash, "Admin", now_epoch)
        log_event(conn, user_id, "user.create", None, "success",
                  json.dumps({"role": "Admin", "bootstrap": True}, separators=(",", ":")),
                  now_epoch)
        return user_id

