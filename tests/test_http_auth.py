import json
import http.client
import os
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

from gestor_inventory.presentation.http_api import HttpApiHandler
from gestor_inventory.security.jwt import create_jwt_hs256


class HttpAuthMiddlewareTests(unittest.TestCase):
    def setUp(self):
        self._prev_secret = HttpApiHandler.jwt_secret
        self._prev_repo = HttpApiHandler.repo
        self._prev_exp = getattr(HttpApiHandler, "jwt_expiration_minutes", 60)

        HttpApiHandler.repo = object()
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

    def _get(self, path: str, headers: dict | None = None) -> tuple[int, dict]:
        conn = http.client.HTTPConnection(self.base[0], self.base[1], timeout=2)
        try:
            conn.request("GET", path, headers=headers or {})
            resp = conn.getresponse()
            raw = resp.read()
            return resp.status, ({} if not raw else json.loads(raw.decode("utf-8")))
        finally:
            conn.close()

    def test_protected_endpoint_requires_bearer_token(self):
        status, body = self._get("/api/auth/me")
        self.assertEqual(status, 401)
        self.assertEqual(body.get("error"), "unauthorized")

    def test_protected_endpoint_accepts_valid_token(self):
        token = create_jwt_hs256(
            {"sub": "1", "company_id": 1, "email": "user@example.com"},
            secret="test-secret",
            expires_in_seconds=60,
        )
        status, body = self._get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(status, 200)
        self.assertEqual(body["company_id"], 1)
        self.assertEqual(body["email"], "user@example.com")
        self.assertIn("exp", body)

    def test_protected_endpoint_rejects_expired_token(self):
        token = create_jwt_hs256(
            {"sub": "1", "company_id": 1, "email": "user@example.com"},
            secret="test-secret",
            expires_in_seconds=-1,
        )
        status, body = self._get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(status, 401)
        self.assertEqual(body.get("error"), "unauthorized")


if __name__ == "__main__":
    unittest.main()
