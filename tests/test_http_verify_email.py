import http.client
import json
import os
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

from gestor_inventory.infrastructure.sqlite_user_repository import SqliteUserRepository
from gestor_inventory.presentation.http_api import HttpApiHandler


class HttpVerifyEmailTests(unittest.TestCase):
    def setUp(self):
        self._prev_secret = HttpApiHandler.jwt_secret
        self._prev_repo = HttpApiHandler.repo
        self._prev_exp = getattr(HttpApiHandler, "jwt_expiration_minutes", 60)

        self.repo = SqliteUserRepository(":memory:")
        HttpApiHandler.repo = self.repo
        HttpApiHandler.jwt_secret = "test-secret"
        HttpApiHandler.jwt_expiration_minutes = 60

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), HttpApiHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base = (host, port)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

        HttpApiHandler.jwt_secret = self._prev_secret
        HttpApiHandler.repo = self._prev_repo
        HttpApiHandler.jwt_expiration_minutes = self._prev_exp

    def _post_json(self, path: str, payload: dict) -> tuple[int, dict]:
        conn = http.client.HTTPConnection(self.base[0], self.base[1], timeout=2)
        try:
            raw = json.dumps(payload).encode("utf-8")
            conn.request(
                "POST",
                path,
                body=raw,
                headers={"Content-Type": "application/json", "Content-Length": str(len(raw))},
            )
            resp = conn.getresponse()
            body_raw = resp.read()
            return resp.status, ({} if not body_raw else json.loads(body_raw.decode("utf-8")))
        finally:
            conn.close()

    def _get(self, path: str) -> tuple[int, dict]:
        conn = http.client.HTTPConnection(self.base[0], self.base[1], timeout=2)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            raw = resp.read()
            return resp.status, ({} if not raw else json.loads(raw.decode("utf-8")))
        finally:
            conn.close()

    def test_register_returns_verification_url_and_verifies_user(self):
        status, body = self._post_json(
            "/api/users/register",
            {"company_id": 1, "email": "user@example.com", "password": "Secret1!", "role_id": 10},
        )
        self.assertEqual(status, 201)
        self.assertIn("verification_url", body)
        self.assertFalse(body["verified"])

        parsed = urlparse(body["verification_url"])
        verify_path = f"{parsed.path}?{parsed.query}"
        status2, body2 = self._get(verify_path)
        self.assertEqual(status2, 200)
        self.assertEqual(body2.get("status"), "ok")

        user = self.repo.get_user_for_login(company_id=1, email="user@example.com")
        self.assertIsNotNone(user)
        self.assertTrue(user["verified"])

    def test_register_rejects_weak_password_with_http_400_and_message(self):
        status, body = self._post_json(
            "/api/users/register",
            {"company_id": 1, "email": "user2@example.com", "password": "weak", "role_id": 10},
        )
        self.assertEqual(status, 400)
        self.assertEqual(body.get("error"), "validation_error")
        self.assertIn("Contraseña débil", body.get("message", ""))


if __name__ == "__main__":
    unittest.main()
