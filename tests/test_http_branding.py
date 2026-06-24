import json
import http.client
import os
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

from gestor_inventory.presentation.http_api import HttpApiHandler
from gestor_inventory.infrastructure.sqlite_user_repository import SqliteUserRepository
from gestor_inventory.application.register_user import RegisterUserRequest, register_user
from gestor_inventory.application.login_user import LoginRequest, login_user


class HttpBrandingTests(unittest.TestCase):
    def setUp(self):
        # Configure in-memory database
        self.repo = SqliteUserRepository(":memory:")
        self.jwt_secret = "test-secret"

        self._prev_secret = HttpApiHandler.jwt_secret
        self._prev_repo = HttpApiHandler.repo

        HttpApiHandler.repo = self.repo
        HttpApiHandler.jwt_secret = self.jwt_secret

        # Start http server
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), HttpApiHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base = (host, port)

        # Set up a test company and user
        self.reg = register_user(
            self.repo,
            RegisterUserRequest(email="admin@branding.com", password="Secret1!", company_name="Branding Co"),
        )
        # Verify the user
        self.repo._persistent_conn.execute(
            "UPDATE users SET verified = 1 WHERE company_id = ? AND id = ?",
            (self.reg.company.id, self.reg.user.id),
        )
        self.repo._persistent_conn.commit()

        # Generate a bearer token
        login_res = login_user(
            self.repo,
            LoginRequest(company_id=self.reg.company.id, email="admin@branding.com", password="Secret1!"),
            jwt_secret=self.jwt_secret,
        )
        self.token = login_res.access_token

        # Mock uploads dir config
        self.prev_uploads_dir = os.environ.get("GI_UPLOADS_DIR")
        self.test_uploads_dir = os.path.join(ROOT, "test_uploads_branding")
        os.environ["GI_UPLOADS_DIR"] = self.test_uploads_dir
        if os.path.exists(self.test_uploads_dir):
            import shutil
            shutil.rmtree(self.test_uploads_dir)
        os.makedirs(self.test_uploads_dir, exist_ok=True)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

        HttpApiHandler.jwt_secret = self._prev_secret
        HttpApiHandler.repo = self._prev_repo

        if self.prev_uploads_dir is not None:
            os.environ["GI_UPLOADS_DIR"] = self.prev_uploads_dir
        else:
            os.environ.pop("GI_UPLOADS_DIR", None)

        if os.path.exists(self.test_uploads_dir):
            import shutil
            shutil.rmtree(self.test_uploads_dir)

    def _request(self, method: str, path: str, body: bytes = b"", headers: dict | None = None) -> tuple[int, bytes, dict]:
        conn = http.client.HTTPConnection(self.base[0], self.base[1], timeout=2)
        try:
            req_headers = {
                "X-Tenant-ID": str(self.reg.company.id),
            }
            if headers:
                req_headers.update(headers)
            conn.request(method, path, body, headers=req_headers)
            resp = conn.getresponse()
            resp_headers = dict(resp.getheaders())
            return resp.status, resp.read(), resp_headers
        finally:
            conn.close()

    def test_login_includes_default_settings(self):
        login_payload = {
            "company_id": self.reg.company.id,
            "email": "admin@branding.com",
            "password": "Secret1!"
        }
        status, data, _ = self._request("POST", "/api/auth/login", body=json.dumps(login_payload).encode())
        self.assertEqual(status, 200)
        body = json.loads(data.decode())
        self.assertIn("settings", body)
        settings = body["settings"]
        self.assertEqual(settings.get("company_name"), "Branding Co")
        self.assertEqual(settings.get("primary_color"), "")
        self.assertEqual(settings.get("secondary_color"), "")
        self.assertEqual(settings.get("accent_color"), "")
        self.assertEqual(settings.get("logo_url"), "")

    def test_update_settings_json_and_get_public_branding(self):
        # Update settings via JSON
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        update_payload = {
            "primary_color": "#111111",
            "secondary_color": "#222222",
            "accent_color": "#333333",
            "company_name": "New Brand Name"
        }
        status, data, _ = self._request("PUT", "/api/admin/settings", body=json.dumps(update_payload).encode(), headers=headers)
        self.assertEqual(status, 200)

        # Retrieve branding settings
        status, data, _ = self._request("GET", "/api/companies/branding")
        self.assertEqual(status, 200)
        body = json.loads(data.decode())
        settings_list = body.get("data", [])
        
        # Turn it into a dictionary
        settings_dict = {item["key"]: item["value"] for item in settings_list}
        self.assertEqual(settings_dict.get("company_name"), "New Brand Name")
        self.assertEqual(settings_dict.get("primary_color"), "#111111")
        self.assertEqual(settings_dict.get("secondary_color"), "#222222")
        self.assertEqual(settings_dict.get("accent_color"), "#333333")

    def test_update_settings_multipart_form_data_with_logo(self):
        # Create a valid 10x10 PNG
        png_data = (
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'
            b'\x00\x00\x00\n\x00\x00\x00\n\x08\x06\x00\x00\x00\x8d2\xcf\xbd'
            b'\x00\x00\x00\x04gAMA\x00\x00\xb1\x8f\x0b\xfc\x61\x05'
            b'\x00\x00\x00\x0cIDATx\x9cc`\x00\x00\x00\x02\x00\x01H\xaf\xa4q'
            b'\x00\x00\x00\x00IEND\xaeB`\x82'
        )

        boundary = "----TestBoundary12345"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="company_name"\r\n\r\n'
            f"Multipart Company Name\r\n"
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="logo"; filename="logo.png"\r\n'
            f"Content-Type: image/png\r\n\r\n"
        ).encode("utf-8") + png_data + f"\r\n--{boundary}--\r\n".encode("utf-8")

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": f"multipart/form-data; boundary={boundary}"
        }

        # Send PUT request
        status, data, _ = self._request("PUT", "/api/admin/settings", body=body, headers=headers)
        self.assertEqual(status, 200)

        # Retrieve settings via login and check values
        login_payload = {
            "company_id": self.reg.company.id,
            "email": "admin@branding.com",
            "password": "Secret1!"
        }
        status, data, _ = self._request("POST", "/api/auth/login", body=json.dumps(login_payload).encode())
        self.assertEqual(status, 200)
        login_body = json.loads(data.decode())
        settings = login_body["settings"]
        self.assertEqual(settings.get("company_name"), "Multipart Company Name")
        
        logo_url = settings.get("logo_url")
        self.assertTrue(logo_url.startswith("http"))
        self.assertTrue(logo_url.endswith(f"/uploads/logos/{self.reg.company.id}.png"))

        # Access/GET the logo file directly via the HTTP server (without Tenant ID header)
        parsed_logo = urlparse(logo_url)
        status, logo_bytes, _ = self._request("GET", parsed_logo.path)
        self.assertEqual(status, 200)
        self.assertEqual(logo_bytes, png_data)

    def test_update_settings_multipart_form_data_invalid_dimensions(self):
        # Create a PNG with width=600, height=600 (0x258 in hex)
        # Big-endian: \x00\x00\x02\x58
        png_data = (
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'
            b'\x00\x00\x02\x58\x00\x00\x02\x58\x08\x06\x00\x00\x00'
            # (remaining IHDR bytes could be anything for simple dimension parse testing)
            b'\x00\x00\x00\x00IEND\xaeB`\x82'
        )

        boundary = "----TestBoundary12345"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="logo"; filename="big_logo.png"\r\n'
            f"Content-Type: image/png\r\n\r\n"
        ).encode("utf-8") + png_data + f"\r\n--{boundary}--\r\n".encode("utf-8")

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": f"multipart/form-data; boundary={boundary}"
        }

        # Send PUT request and assert 400 validation error
        status, data, _ = self._request("PUT", "/api/admin/settings", body=body, headers=headers)
        self.assertEqual(status, 400)
        body_json = json.loads(data.decode())
        self.assertFalse(body_json.get("success"))
        self.assertIn("Las dimensiones de la imagen no deben exceder 500x500 píxeles", body_json.get("error"))


if __name__ == "__main__":
    unittest.main()
