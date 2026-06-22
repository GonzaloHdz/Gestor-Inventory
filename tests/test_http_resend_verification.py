import http.client
import json
import os
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

from gestor_inventory.infrastructure.sqlite_user_repository import SqliteUserRepository
from gestor_inventory.presentation.http_api import HttpApiHandler
from gestor_inventory.security.jwt import create_jwt_hs256


class FakeEmailSender:
    def __init__(self):
        self.sent_messages: list[dict] = []

    def send_verification_email(self, *, to_email: str, verification_url: str) -> None:
        self.sent_messages.append({"to_email": to_email, "verification_url": verification_url})


class HttpResendVerificationTests(unittest.TestCase):
    def setUp(self):
        self._prev_secret = HttpApiHandler.jwt_secret
        self._prev_repo = HttpApiHandler.repo
        self._prev_exp = getattr(HttpApiHandler, "jwt_expiration_minutes", 60)
        self._prev_refresh_exp = getattr(HttpApiHandler, "refresh_token_expiration_minutes", 10080)
        self._prev_email_sender = getattr(HttpApiHandler, "email_sender", None)
        self._prev_public_base_url = getattr(HttpApiHandler, "public_base_url", None)

        self.repo = SqliteUserRepository(":memory:")
        self.sender = FakeEmailSender()
        HttpApiHandler.repo = self.repo
        HttpApiHandler.jwt_secret = "test-secret"
        HttpApiHandler.jwt_expiration_minutes = 60
        HttpApiHandler.refresh_token_expiration_minutes = 10080
        HttpApiHandler.email_sender = self.sender
        HttpApiHandler.public_base_url = "http://app.test"

        self.admin_user, _ = self.repo.create_user_with_role(
            company_id=1,
            email="admin@example.com",
            password_hash="hash-admin",
            role_id=12,
        )

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
        HttpApiHandler.email_sender = self._prev_email_sender
        HttpApiHandler.public_base_url = self._prev_public_base_url

    def _post_json(self, path: str, payload: dict, token: str | None = None) -> tuple[int, dict]:
        conn = http.client.HTTPConnection(self.base[0], self.base[1], timeout=2)
        try:
            raw = json.dumps(payload).encode("utf-8")
            headers = {"Content-Type": "application/json", "Content-Length": str(len(raw))}
            if token is not None:
                headers["Authorization"] = f"Bearer {token}"
            conn.request("POST", path, body=raw, headers=headers)
            resp = conn.getresponse()
            body_raw = resp.read()
            return resp.status, ({} if not body_raw else json.loads(body_raw.decode("utf-8")))
        finally:
            conn.close()

    def _token_for(self, *, user_id: int, company_id: int, email: str) -> str:
        return create_jwt_hs256(
            {"sub": str(user_id), "company_id": int(company_id), "email": str(email)},
            secret="test-secret",
            expires_in_seconds=60,
        )

    def test_register_sends_verification_email(self):
        status, body = self._post_json(
            "/api/users/register",
            {"company_name": "Empresa Mail", "email": "user@example.com", "password": "Secret1!"},
        )
        self.assertEqual(status, 201)
        self.assertTrue(body.get("verification_email_sent"))
        self.assertEqual(len(self.sender.sent_messages), 1)
        self.assertEqual(self.sender.sent_messages[0]["to_email"], "user@example.com")
        self.assertEqual(self.sender.sent_messages[0]["verification_url"], body["verification_url"])

    def test_create_internal_user_sends_verification_email(self):
        token = self._token_for(user_id=self.admin_user.id, company_id=1, email=self.admin_user.email)
        status, body = self._post_json(
            "/api/admin/users",
            {"email": "interno@example.com", "password": "Secret1!", "role_id": 10},
            token=token,
        )
        self.assertEqual(status, 201)
        self.assertTrue(body.get("verification_email_sent"))
        self.assertEqual(len(self.sender.sent_messages), 1)
        self.assertEqual(self.sender.sent_messages[0]["to_email"], "interno@example.com")

    def test_resend_verification_sends_new_email(self):
        status_reg, body_reg = self._post_json(
            "/api/users/register",
            {"company_name": "Empresa Reenvio", "email": "pending@example.com", "password": "Secret1!"},
        )
        self.assertEqual(status_reg, 201)
        self.sender.sent_messages.clear()

        status_resend, body_resend = self._post_json(
            "/api/auth/resend-verification",
            {"company_id": body_reg["company_id"], "email": "pending@example.com"},
        )
        self.assertEqual(status_resend, 200)
        self.assertEqual(body_resend.get("status"), "ok")
        self.assertTrue(body_resend.get("sent"))
        self.assertEqual(len(self.sender.sent_messages), 1)
        self.assertEqual(self.sender.sent_messages[0]["to_email"], "pending@example.com")


if __name__ == "__main__":
    unittest.main()
