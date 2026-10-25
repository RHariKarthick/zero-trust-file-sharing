"""Local Streamlit dashboard. All remote operations go through ``client.api``."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unicodedata

import streamlit as st

from client import api as client_api
from client.errors import ClientError
from client.protocol import MAX_FILE_BYTES


st.set_page_config(page_title="Zero Trust File Sharing", page_icon="🔐", layout="wide")

_TOKEN_KEY = "zts_token"
_USER_KEY = "zts_user"
_EXPIRY_KEY = "zts_expires_at"
_DOWNLOAD_KEY = "zts_prepared_download"
_NOTICE_KEY = "zts_notice"


def _clear_session() -> None:
    for key in (_TOKEN_KEY, _USER_KEY, _EXPIRY_KEY, _DOWNLOAD_KEY):
        st.session_state.pop(key, None)


def _invoke(operation, success_message: str | None = None) -> tuple[bool, object | None]:
    """Call a public API function and show only its safe error message."""
    try:
        result = operation()
    except ClientError as exc:
        if exc.code in {"AUTH_REQUIRED", "SESSION_EXPIRED"}:
            _clear_session()
            st.session_state[_NOTICE_KEY] = ("warning", "Your session is no longer valid. Log in again to continue.")
            st.rerun()
        st.error(f"{exc.message} (code: {exc.code})")
        return False, None
    except OSError:
        st.error("A local file or destination could not be accessed.")
        return False, None
    except Exception:
        # Avoid showing exception details that could contain local paths or data.
        st.error("The operation failed because of an unexpected local error.")
        return False, None
    if success_message:
        st.success(success_message)
    return True, result


def _valid_upload_name(name: str) -> bool:
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return (
        1 <= len(encoded) <= 255
        and name == unicodedata.normalize("NFC", name)
        and name not in {".", ".."}
        and not any(char in name for char in ("/", "\\", "\x00"))
        and not any(unicodedata.category(char) == "Cc" for char in name)
    )


def _display_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KiB"
    return f"{size_bytes / (1024 * 1024):.2f} MiB"


def _login_page() -> None:
    st.title("🔐 Zero Trust File Sharing")
    st.caption("Local file sharing with mutual TLS, account authentication, access controls, and integrity checks.")
    with st.form("login_form", clear_on_submit=True):
        username = st.text_input("Username", key="login_username", autocomplete="username")
        password = st.text_input("Password", type="password", key="login_password", autocomplete="current-password")
        submitted = st.form_submit_button("Log in", type="primary")
    if submitted:
        succeeded, result = _invoke(lambda: client_api.login(username, password))
        if succeeded and isinstance(result, dict):
            st.session_state[_TOKEN_KEY] = result["token"]
            st.session_state[_USER_KEY] = result["user"]
            st.session_state[_EXPIRY_KEY] = result["expires_at"]
            st.session_state.pop(_DOWNLOAD_KEY, None)
            st.session_state[_NOTICE_KEY] = ("success", "Signed in successfully.")
            st.rerun()
    st.info("The client also requires the local CA and device certificate configured for this computer.")


def _logout(token: str) -> None:
    succeeded, _ = _invoke(lambda: client_api.logout(token))
    # Clear local credentials even if the server cannot be reached.
    _clear_session()
    if succeeded:
        st.session_state[_NOTICE_KEY] = ("success", "You have been signed out.")
    else:
        st.session_state[_NOTICE_KEY] = ("warning", "Local session state was cleared. The server session will expire automatically if it was not revoked.")
    st.rerun()


def _render_upload(token: str) -> None:
    st.subheader("Upload a file")
    with st.form("upload_form", clear_on_submit=True):
        uploaded = st.file_uploader(
            "Choose a file (maximum 50 MiB)", key="upload_file", max_upload_size=50,
        )
        recipient_text = st.text_input("Share with usernames (optional, comma-separated)")
        submitted = st.form_submit_button("Upload", type="primary")
    if not submitted:
        return
    if uploaded is None:
        st.error("Choose a file before uploading.")
        return
    if not _valid_upload_name(uploaded.name):
        st.error("The filename is invalid. Use a plain filename without path separators or control characters.")
        return
    if uploaded.size > MAX_FILE_BYTES:
        st.error("The selected file exceeds the 50 MiB limit.")
        return
    recipients = [value.strip() for value in recipient_text.split(",") if value.strip()]
    if len({value.casefold() for value in recipients}) != len(recipients):
        st.error("Enter each sharing username only once.")
        return
    try:
        with tempfile.TemporaryDirectory(prefix="zts-ui-upload-") as temp_dir:
            source = Path(temp_dir) / uploaded.name
            source.write_bytes(uploaded.getvalue())
            _invoke(lambda: client_api.upload_file(token, source, recipients), "File uploaded and encrypted successfully.")
    except OSError:
        st.error("The selected file could not be prepared for upload.")


def _render_files(token: str) -> list[dict]:
    st.subheader("Your accessible files")
    succeeded, files = _invoke(lambda: client_api.list_files(token))
    if not succeeded or not isinstance(files, list):
        return []
    if not files:
        st.info("No files are currently available to this account.")
        return []
    display_rows = [
        {
            "ID": row["file_id"],
            "Filename": row["filename"],
            "Owner": row["owner_username"],
            "Size": _display_size(row["size_bytes"]),
            "Access": row["access"],
            "SHA-256": row["sha256_hex"],
            "Created (UTC)": datetime.fromtimestamp(row["created_at"], timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        }
        for row in files
    ]
    st.dataframe(display_rows, width="stretch", hide_index=True)
    return files


def _render_download(token: str, files: list[dict]) -> None:
    if not files:
        return
    st.subheader("Download")
    by_id = {row["file_id"]: row for row in files}
    selected_id = st.selectbox(
        "Select a file",
        options=list(by_id),
        format_func=lambda file_id: f"{by_id[file_id]['filename']} (ID {file_id})",
        key="download_file_id",
    )
    if st.button("Prepare verified download", key="prepare_download"):
        st.session_state.pop(_DOWNLOAD_KEY, None)
        row = by_id[selected_id]
        try:
            with tempfile.TemporaryDirectory(prefix="zts-ui-download-") as temp_dir:
                destination = Path(temp_dir) / "verified-download"
                succeeded, _ = _invoke(
                    lambda: client_api.download_file(token, selected_id, destination),
                    "Download received and verified against its SHA-256 digest.",
                )
                if succeeded:
                    st.session_state[_DOWNLOAD_KEY] = {
                        "filename": row["filename"],
                        "data": destination.read_bytes(),
                    }
        except OSError:
            st.session_state.pop(_DOWNLOAD_KEY, None)
            st.error("The verified download could not be prepared for your browser.")
    prepared = st.session_state.get(_DOWNLOAD_KEY)
    if isinstance(prepared, dict) and isinstance(prepared.get("data"), bytes):
        st.download_button(
            "Save verified file",
            data=prepared["data"],
            file_name=prepared["filename"],
            mime="application/octet-stream",
            key="save_verified_download",
        )


def _render_file_controls(token: str, user: dict, files: list[dict]) -> None:
    if not files:
        return
    by_id = {row["file_id"]: row for row in files}
    st.subheader("File access and deletion")
    selected_id = st.selectbox(
        "Choose a file to manage",
        options=list(by_id),
        format_func=lambda file_id: f"{by_id[file_id]['filename']} (ID {file_id})",
        key="manage_file_id",
    )
    selected = by_id[selected_id]
    owns_file = selected["owner_username"] == user["username"]
    admin = user["role"] == "Admin"
    if owns_file or admin:
        with st.form("grant_access_form", clear_on_submit=True):
            grant_username = st.text_input("Username to grant access")
            grant_submitted = st.form_submit_button("Grant download access")
        if grant_submitted:
            if not grant_username.strip():
                st.error("Enter a username.")
            else:
                _invoke(
                    lambda: client_api.grant_file_access(token, selected_id, grant_username.strip()),
                    "File access granted.",
                )
        with st.form("revoke_access_form", clear_on_submit=True):
            revoke_username = st.text_input("Username whose access to revoke")
            revoke_submitted = st.form_submit_button("Revoke download access")
        if revoke_submitted:
            if not revoke_username.strip():
                st.error("Enter a username.")
            else:
                _invoke(
                    lambda: client_api.revoke_file_access(token, selected_id, revoke_username.strip()),
                    "File access revoked.",
                )
        st.caption("The backend does not expose a grant-list operation; enter the username to revoke directly.")
    else:
        st.caption("Only the file owner or an Admin can change sharing permissions.")

    can_delete = admin or owns_file
    with st.form("delete_file_form"):
        confirmed = st.checkbox(f"Confirm deletion of {selected['filename']}", disabled=not can_delete)
        delete_submitted = st.form_submit_button("Delete file", type="secondary", disabled=not can_delete)
    if delete_submitted:
        if not confirmed:
            st.error("Confirm the deletion before continuing.")
        else:
            succeeded, _ = _invoke(lambda: client_api.delete_file(token, selected_id), "File deleted.")
            if succeeded:
                st.session_state.pop(_DOWNLOAD_KEY, None)
                st.rerun()


def _render_admin(token: str, user: dict) -> None:
    st.header("Administration")
    with st.form("create_user_form", clear_on_submit=True):
        st.subheader("Create account")
        username = st.text_input("New username", key="new_username")
        password = st.text_input("New account password", type="password", key="new_password")
        role = st.selectbox("Initial role", ["User", "Admin"], key="new_role")
        submitted = st.form_submit_button("Create user")
    if submitted:
        succeeded, result = _invoke(
            lambda: client_api.admin_create_user(token, username.strip(), password, role),
            "Account created.",
        )
        if succeeded:
            st.info(f"New user ID: {result}. Keep this ID available for account management.")

    st.caption("The API does not provide a user-directory operation. Enter the target account's numeric user ID.")
    role_column, active_column = st.columns(2)
    with role_column:
        with st.form("set_role_form"):
            st.subheader("Change role")
            role_user_id = st.number_input("User ID", min_value=1, step=1, key="role_user_id")
            new_role = st.selectbox("Role", ["User", "Admin"], key="role_to_set")
            role_submitted = st.form_submit_button("Apply role")
        if role_submitted:
            succeeded, _ = _invoke(
                lambda: client_api.admin_set_user_role(token, int(role_user_id), new_role),
                "User role updated.",
            )
            if succeeded and int(role_user_id) == user["user_id"]:
                st.session_state[_USER_KEY] = {**user, "role": new_role}
                st.session_state[_NOTICE_KEY] = ("success", "Your role has been updated.")
                st.rerun()
    with active_column:
        with st.form("set_active_form"):
            st.subheader("Account status")
            active_user_id = st.number_input("User ID", min_value=1, step=1, key="active_user_id")
            active_state = st.selectbox("Status", ["Active", "Deactivated"], key="active_state")
            active_submitted = st.form_submit_button("Apply status")
        if active_submitted:
            succeeded, _ = _invoke(
                lambda: client_api.admin_set_user_active(token, int(active_user_id), active_state == "Active"),
                "User account status updated.",
            )
            if succeeded and int(active_user_id) == user["user_id"] and active_state == "Deactivated":
                _clear_session()
                st.session_state[_NOTICE_KEY] = ("warning", "This account is deactivated and has been signed out.")
                st.rerun()


def main() -> None:
    notice = st.session_state.pop(_NOTICE_KEY, None)
    if isinstance(notice, tuple) and len(notice) == 2 and all(isinstance(part, str) for part in notice):
        if notice[0] == "success":
            st.success(notice[1])
        else:
            st.warning(notice[1])
    token = st.session_state.get(_TOKEN_KEY)
    user = st.session_state.get(_USER_KEY)
    if not isinstance(token, str) or not isinstance(user, dict):
        _login_page()
        return

    st.title("🔐 Zero Trust File Sharing")
    st.sidebar.write(f"Signed in as **{user['username']}** · {user['role']}")
    expires_at = st.session_state.get(_EXPIRY_KEY)
    if isinstance(expires_at, int):
        st.sidebar.caption("Session expires at " + datetime.fromtimestamp(expires_at, timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    if st.sidebar.button("Log out", key="logout"):
        _logout(token)

    _render_upload(token)
    files = _render_files(token)
    _render_download(token, files)
    _render_file_controls(token, user, files)
    if user.get("role") == "Admin":
        _render_admin(token, user)


main()
