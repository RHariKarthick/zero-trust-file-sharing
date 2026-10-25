"""Streamlit dashboard smoke tests without network or credential logging."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from client.errors import ClientError
from streamlit.testing.v1 import AppTest

_APP = Path(__file__).resolve().parents[1] / "ui" / "app.py"
_TOKEN = "t" * 43


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The sandbox's system TEMP can be read-only; Streamlit's AppTest creates
        # a short-lived script there, so keep that temporary file in tests/.
        cls._old_tempdir = tempfile.tempdir
        tempfile.tempdir = str(Path(__file__).resolve().parent)

    @classmethod
    def tearDownClass(cls):
        tempfile.tempdir = cls._old_tempdir

    def _signed_in(self, role="User"):
        app = AppTest.from_file(str(_APP)).run(timeout=10)
        login_data = {
            "token": _TOKEN,
            "expires_at": 2_000_000_000,
            "user": {"user_id": 7, "username": "demo", "role": role},
        }
        with patch("client.api.login", return_value=login_data), patch("client.api.list_files", return_value=[]):
            app.text_input(key="login_username").set_value("demo")
            app.text_input(key="login_password").set_value("a masked password")
            app.button(key="FormSubmitter:login_form-Log in").click()
            app.run(timeout=10)
        self.assertFalse(app.exception)
        return app

    def test_login_stores_token_in_session_state_without_rendering_it(self):
        app = self._signed_in()
        self.assertEqual(app.session_state["zts_token"], _TOKEN)
        self.assertTrue(any("Signed in successfully" in item.value for item in app.success))
        rendered_text = " ".join(item.value for item in app.markdown)
        self.assertNotIn(_TOKEN, rendered_text)
        self.assertIn("demo", rendered_text)

    def test_expired_session_clears_authentication_and_shows_notice(self):
        app = self._signed_in()
        with patch("client.api.list_files", side_effect=ClientError("SESSION_EXPIRED", "safe expiry message")):
            app.run(timeout=10)
        self.assertNotIn("zts_token", app.session_state)
        self.assertTrue(any("no longer valid" in item.value for item in app.warning))
        self.assertFalse(app.exception)

    def test_admin_controls_render_and_logout_clears_local_token(self):
        app = self._signed_in(role="Admin")
        self.assertEqual(len(app.number_input), 2)
        self.assertTrue(any(widget.label == "New account password" for widget in app.text_input))
        with patch("client.api.logout", return_value=None):
            app.button(key="logout").click()
            app.run(timeout=10)
        self.assertNotIn("zts_token", app.session_state)
        self.assertTrue(any("signed out" in item.value.lower() for item in app.success))
        self.assertFalse(app.exception)

    def test_upload_uses_client_api_and_preserves_the_validated_filename(self):
        app = self._signed_in()
        observed = {}

        def capture_upload(token, source, recipients):
            observed.update(token=token, filename=source.name, content=source.read_bytes(), recipients=recipients)
            return {"file_id": 31, "sha256_hex": "a" * 64}

        with patch("client.api.upload_file", side_effect=capture_upload), patch("client.api.list_files", return_value=[]):
            app.file_uploader(key="upload_file").upload("notes.txt", b"sample bytes")
            app.button(key="FormSubmitter:upload_form-Upload").click()
            app.run(timeout=10)
        self.assertEqual(observed, {
            "token": _TOKEN, "filename": "notes.txt", "content": b"sample bytes", "recipients": [],
        })
        self.assertTrue(any("uploaded and encrypted" in item.value.lower() for item in app.success))
        self.assertFalse(app.exception)

    def test_download_delegates_verification_to_client_api_before_offering_save(self):
        app = self._signed_in()
        payload = b"verified by the client API"
        row = {
            "file_id": 23,
            "filename": "report.txt",
            "owner_username": "demo",
            "size_bytes": len(payload),
            "sha256_hex": "b" * 64,
            "created_at": 1_800_000_000,
            "access": "owner",
        }

        def write_verified_file(token, file_id, destination):
            self.assertEqual((token, file_id), (_TOKEN, 23))
            destination.write_bytes(payload)
            return {"filename": "report.txt", "size_bytes": len(payload), "sha256_hex": "b" * 64}

        with patch("client.api.list_files", return_value=[row]), patch(
            "client.api.download_file", side_effect=write_verified_file,
        ) as download:
            app.run(timeout=10)
            app.button(key="prepare_download").click()
            app.run(timeout=10)
        download.assert_called_once()
        self.assertEqual(app.session_state["zts_prepared_download"], {"filename": "report.txt", "data": payload})
        self.assertTrue(any(button.label == "Save verified file" for button in app.get("download_button")))
        self.assertFalse(app.exception)


if __name__ == "__main__":
    unittest.main()
