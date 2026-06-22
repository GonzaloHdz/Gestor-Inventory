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
from gestor_inventory.security.jwt import verify_jwt_hs256


class HttpRefreshTokenTests(unittest.TestCase):
    def setUp(self):
        self._prev_secret = HttpApiHandler.jwt_secret
        self._prev_repo = HttpApiHandler.repo
        self._prev_exp = getattr(HttpApiHandler, "jwt_expiration_minutes", 60)
        self._prev_refresh_exp = getattr(HttpApiHandler, "refresh_token_expiration_minutes", 10080)

        self.repo = SqliteUserRepository(":memory:")
        HttpApiHandler.repo = self.repo
        HttpApiHandler.jwt_secret = "test-secret"
        HttpApiHandler.jwt_expiration_minutes = 60
        HttpApiHandler.refresh_token_expiration_minutes = 60 * 24 * 7

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
        HttpApiHandler.refresh_token_expiration_minutes = self._prev_refresh_exp

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

    def _register_and_verify(self) -> dict:
        status_reg, body_reg = self._post_json(
            "/api/users/register",
            {"company_name": "Empresa Refresh", "email": "refresh@example.com", "password": "Secret1!"},
        )
        self.assertEqual(status_reg, 201)
        parsed = urlparse(body_reg["verification_url"])
        status_verify, _ = self._get(f"{parsed.path}?{parsed.query}")
        self.assertEqual(status_verify, 200)
        return body_reg

    def test_login_returns_access_and_refresh_tokens(self):
        reg = self._register_and_verify()
        status_login, body_login = self._post_json(
            "/api/auth/login",
            {"company_id": reg["company_id"], "email": "refresh@example.com", "password": "Secret1!"},
        )
        self.assertEqual(status_login, 200)
        self.assertIn("access_token", body_login)
        self.assertIn("refresh_token", body_login)

    def test_refresh_returns_new_tokens_and_rotates_old_refresh_token(self):
        reg = self._register_and_verify()
        status_login, body_login = self._post_json(
            "/api/auth/login",
            {"company_id": reg["company_id"], "email": "refresh@example.com", "password": "Secret1!"},
        )
        self.assertEqual(status_login, 200)

        status_refresh_1, body_refresh_1 = self._post_json(
            "/api/auth/refresh",
            {"company_id": reg["company_id"], "refresh_token": body_login["refresh_token"]},
        )
        self.assertEqual(status_refresh_1, 200)
        self.assertIn("access_token", body_refresh_1)
        self.assertIn("refresh_token", body_refresh_1)
        self.assertNotEqual(body_refresh_1["refresh_token"], body_login["refresh_token"])

        payload = verify_jwt_hs256(body_refresh_1["access_token"], secret="test-secret")
        self.assertEqual(payload["company_id"], reg["company_id"])
        self.assertEqual(payload["email"], "refresh@example.com")

        status_refresh_2, body_refresh_2 = self._post_json(
            "/api/auth/refresh",
            {"company_id": reg["company_id"], "refresh_token": body_login["refresh_token"]},
        )
        self.assertEqual(status_refresh_2, 401)
        self.assertEqual(body_refresh_2.get("error"), "invalid_refresh_token")

    def test_refresh_rejects_invalid_payload(self):
        status, body = self._post_json("/api/auth/refresh", {"company_id": 1})
        self.assertEqual(status, 400)
        self.assertEqual(body.get("error"), "invalid_payload")

    def test_logout_invalidates_refresh_token(self):
        reg = self._register_and_verify()
        status_login, body_login = self._post_json(
            "/api/auth/login",
            {"company_id": reg["company_id"], "email": "refresh@example.com", "password": "Secret1!"},
        )
        self.assertEqual(status_login, 200)

        status_logout, body_logout = self._post_json(
            "/api/auth/logout",
            {"company_id": reg["company_id"], "refresh_token": body_login["refresh_token"]},
        )
        self.assertEqual(status_logout, 200)
        self.assertEqual(body_logout.get("status"), "ok")

        status_refresh, body_refresh = self._post_json(
            "/api/auth/refresh",
            {"company_id": reg["company_id"], "refresh_token": body_login["refresh_token"]},
        )
        self.assertEqual(status_refresh, 401)
        self.assertEqual(body_refresh.get("error"), "invalid_refresh_token")

    def test_logout_rejects_invalid_payload(self):
        status, body = self._post_json("/api/auth/logout", {"company_id": 1})
        self.assertEqual(status, 400)
        self.assertEqual(body.get("error"), "invalid_payload")


if __name__ == "__main__":
    unittest.main()
