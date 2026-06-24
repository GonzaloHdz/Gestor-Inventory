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

from gestor_inventory import config
from gestor_inventory.domain.errors import EmailAlreadyExistsError, ValidationError
from gestor_inventory.infrastructure.sqlite_user_repository import SqliteUserRepository
from gestor_inventory.presentation.http_api import HttpApiHandler
from gestor_inventory.security.jwt import create_jwt_hs256
from gestor_inventory.application.invite_employee import invite_employee, InviteEmployeeRequest
from gestor_inventory.application.set_password import set_password, SetPasswordRequest


class EmployeeInvitationTests(unittest.TestCase):
    def setUp(self):
        self._prev_secret = HttpApiHandler.jwt_secret
        self._prev_repo = HttpApiHandler.repo
        self._prev_exp = getattr(HttpApiHandler, "jwt_expiration_minutes", 60)
        self._prev_demo = getattr(HttpApiHandler, "demo_mode", False)

        self.repo = SqliteUserRepository(":memory:")
        HttpApiHandler.repo = self.repo
        HttpApiHandler.jwt_secret = "test-secret"
        HttpApiHandler.jwt_expiration_minutes = 60
        HttpApiHandler.demo_mode = True  # set demo mode to true by default for tests

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), HttpApiHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base = (host, port)

        # Seed initial admin user and company
        self.company = self.repo.create_company(name="Test Corp", currency="USD", timezone="UTC", created_at=1000, is_verified=1)
        self.admin, _ = self.repo.create_user_with_role(
            company_id=self.company.id,
            email="admin@testcorp.com",
            password_hash="admin-hash",
            role_id=12,  # Administrador
        )
        # Generate token for admin
        self.admin_token = create_jwt_hs256(
            {"sub": str(self.admin.id), "company_id": self.company.id, "email": self.admin.email},
            secret="test-secret",
            expires_in_seconds=60,
        )

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

        HttpApiHandler.jwt_secret = self._prev_secret
        HttpApiHandler.repo = self._prev_repo
        HttpApiHandler.jwt_expiration_minutes = self._prev_exp
        HttpApiHandler.demo_mode = self._prev_demo

    def _post_json(self, path: str, payload: dict, headers: dict | None = None) -> tuple[int, dict]:
        conn = http.client.HTTPConnection(self.base[0], self.base[1], timeout=2)
        try:
            raw = json.dumps(payload).encode("utf-8")
            h = {"Content-Type": "application/json", "Content-Length": str(len(raw))}
            if headers:
                h.update(headers)
            conn.request(
                "POST",
                path,
                body=raw,
                headers=h,
            )
            resp = conn.getresponse()
            body_raw = resp.read()
            return resp.status, ({} if not body_raw else json.loads(body_raw.decode("utf-8")))
        finally:
            conn.close()

    def test_invite_employee_unit_success(self):
        res = invite_employee(
            self.repo,
            InviteEmployeeRequest(
                admin_company_id=self.company.id,
                email="emp1@testcorp.com",
                role="employee"
            ),
            base_url="http://127.0.0.1:8000"
        )
        self.assertEqual(res.company_name, "Test Corp")
        self.assertEqual(res.user.email, "emp1@testcorp.com")
        self.assertFalse(res.user.verified)
        self.assertEqual(res.user.password_hash, "")
        self.assertTrue(res.verification_token)
        self.assertIn("/set-password?token=", res.verification_url)

    def test_invite_employee_unit_duplicate_email(self):
        invite_employee(
            self.repo,
            InviteEmployeeRequest(admin_company_id=self.company.id, email="emp2@testcorp.com"),
        )
        with self.assertRaises(EmailAlreadyExistsError):
            invite_employee(
                self.repo,
                InviteEmployeeRequest(admin_company_id=self.company.id, email="emp2@testcorp.com"),
            )

    def test_set_password_unit_success(self):
        res = invite_employee(
            self.repo,
            InviteEmployeeRequest(admin_company_id=self.company.id, email="emp3@testcorp.com"),
        )
        # Call set_password
        set_password(
            self.repo,
            SetPasswordRequest(token=res.verification_token, new_password="SecretPass123!")
        )
        # Check that user is updated
        user = self.repo.get_user_by_id(company_id=self.company.id, user_id=res.user.id)
        self.assertIsNotNone(user)
        self.assertTrue(user.verified)
        self.assertTrue(len(user.password_hash) > 0)
        self.assertIsNone(user.verification_token)

    def test_http_invite_and_set_password_demo_mode(self):
        # 1. Invite employee via HTTP POST /api/employees/invite
        status_invite, body_invite = self._post_json(
            "/api/employees/invite",
            {"email": "invited@testcorp.com", "role": "employee"},
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(status_invite, 200)
        self.assertEqual(body_invite.get("status"), "ok")
        self.assertIn("demo_token", body_invite)
        demo_token = body_invite["demo_token"]

        # 2. Set password via HTTP POST /api/auth/set-password
        status_set, body_set = self._post_json(
            "/api/auth/set-password",
            {"token": demo_token, "new_password": "SecurePassword1!"}
        )
        self.assertEqual(status_set, 200)
        self.assertEqual(body_set.get("status"), "ok")

        # 3. Log in with the new employee
        status_login, body_login = self._post_json(
            "/api/auth/login",
            {
                "company_id": self.company.id,
                "email": "invited@testcorp.com",
                "password": "SecurePassword1!"
            }
        )
        self.assertEqual(status_login, 200)
        self.assertIn("access_token", body_login)


if __name__ == "__main__":
    unittest.main()
