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
from gestor_inventory.security.password_hash import hash_password


class HttpTenantHeaderTests(unittest.TestCase):
    def setUp(self):
        self._prev_secret = HttpApiHandler.jwt_secret
        self._prev_repo = HttpApiHandler.repo
        self._prev_exp = getattr(HttpApiHandler, "jwt_expiration_minutes", 60)

        self.repo = SqliteUserRepository(":memory:")
        HttpApiHandler.repo = self.repo
        HttpApiHandler.jwt_secret = "test-secret"
        HttpApiHandler.jwt_expiration_minutes = 60

        self.repo.create_company(name="Company 1", currency="MXN", timezone="UTC", created_at=123)
        self.repo.create_company(name="Company 2", currency="MXN", timezone="UTC", created_at=123)
        conn = self.repo._persistent_conn
        conn.execute("UPDATE companies SET status = 'inactive' WHERE id = 2")
        conn.commit()

        password_hash_v = hash_password("Strong1!")
        self.user, _ = self.repo.create_user_with_role(
            company_id=1, email="admin@example.com", password_hash=password_hash_v, role_id=12
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

    def _token_for(self, *, user_id: int, company_id: int, email: str) -> str:
        return create_jwt_hs256(
            {"sub": str(user_id), "company_id": int(company_id), "email": str(email)},
            secret="test-secret",
            expires_in_seconds=60,
        )

    def _request(self, method: str, path: str, body: dict | None = None, headers: dict | None = None) -> tuple[int, dict]:
        conn = http.client.HTTPConnection(self.base[0], self.base[1], timeout=2)
        try:
            req_headers = {}
            if headers:
                req_headers.update(headers)
            raw = None
            if body is not None:
                raw = json.dumps(body).encode("utf-8")
                req_headers["Content-Type"] = "application/json"
            conn.request(method, path, body=raw, headers=req_headers)
            resp = conn.getresponse()
            raw_resp = resp.read()
            return resp.status, ({} if not raw_resp else json.loads(raw_resp.decode("utf-8")))
        finally:
            conn.close()

    def test_cors_preflight_allows_x_tenant_id_header(self):
        conn = http.client.HTTPConnection(self.base[0], self.base[1], timeout=2)
        try:
            conn.request("OPTIONS", "/api/auth/login", headers={"Origin": "http://127.0.0.1:5500"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 204)
            allow_headers = resp.getheader("Access-Control-Allow-Headers")
            self.assertIn("X-Tenant-ID", allow_headers)
        finally:
            conn.close()

    def test_rejects_invalid_x_tenant_id_value(self):
        status, body = self._request("GET", "/api/companies/branding", headers={"X-Tenant-ID": "abc"})
        self.assertEqual(status, 400)
        self.assertIn("Inquilino inválido", body.get("error", ""))

        status, body = self._request("GET", "/api/companies/branding", headers={"X-Tenant-ID": "-5"})
        self.assertEqual(status, 400)
        self.assertIn("Inquilino inválido", body.get("error", ""))

    def test_rejects_inactive_or_nonexistent_tenant(self):
        status, body = self._request("GET", "/api/companies/branding", headers={"X-Tenant-ID": "999"})
        self.assertEqual(status, 403)
        self.assertIn("Inquilino no encontrado o inactivo", body.get("error", ""))

        status, body = self._request("GET", "/api/companies/branding", headers={"X-Tenant-ID": "2"})
        self.assertEqual(status, 403)
        self.assertIn("Inquilino no encontrado o inactivo", body.get("error", ""))

    def test_public_branding_endpoint_succeeds_with_active_tenant(self):
        self.repo.upsert_company_setting(company_id=1, setting_key="logo", setting_value="http://logo.png", now=123)
        status, body = self._request("GET", "/api/companies/branding", headers={"X-Tenant-ID": "1"})
        self.assertEqual(status, 200)
        data = body.get("data", [])
        self.assertTrue(any(x.get("key") == "logo" and x.get("value") == "http://logo.png" for x in data))

    def test_login_harmony_with_x_tenant_id(self):
        status, body = self._request(
            "POST", "/api/auth/login",
            body={"company_id": 1, "email": "admin@example.com", "password": "Strong1!"},
            headers={"X-Tenant-ID": "1"}
        )
        self.assertEqual(status, 403)
        self.assertIn("verificar", body.get("error", ""))

        status, body = self._request(
            "POST", "/api/auth/login",
            body={"company_id": 1, "email": "admin@example.com", "password": "Strong1!"},
            headers={"X-Tenant-ID": "2"}
        )
        self.assertEqual(status, 403)
        self.assertIn("Inquilino no encontrado o inactivo", body.get("error", ""))

        self.repo.create_company(name="Company 3", currency="MXN", timezone="UTC", created_at=123)
        status, body = self._request(
            "POST", "/api/auth/login",
            body={"company_id": 1, "email": "admin@example.com", "password": "Strong1!"},
            headers={"X-Tenant-ID": "3"}
        )
        self.assertEqual(status, 400)
        self.assertIn("inquilino no coincide", body.get("error", ""))

    def test_protected_route_harmony_with_x_tenant_id(self):
        token_1 = self._token_for(user_id=self.user.id, company_id=1, email=self.user.email)

        status, body = self._request("GET", "/api/auth/me", headers={"Authorization": f"Bearer {token_1}", "X-Tenant-ID": "1"})
        self.assertEqual(status, 200)

        self.repo.create_company(name="Company 3", currency="MXN", timezone="UTC", created_at=123)
        status, body = self._request("GET", "/api/auth/me", headers={"Authorization": f"Bearer {token_1}", "X-Tenant-ID": "3"})
        self.assertEqual(status, 403)
        self.assertIn("inquilino no coincide con el token", body.get("error", ""))

    def test_register_vulnerability_protection(self):
        # 1. Without X-Tenant-ID header, arbitrary company_id/role_id are stripped and registration succeeds
        status, body = self._request(
            "POST", "/api/users/register",
            body={"email": "hacker@example.com", "password": "Strong1!", "role_id": 12, "company_id": 999, "company_name": "Hack Ltd"}
        )
        self.assertEqual(status, 201)

        # 2. With X-Tenant-ID header, mismatched company_id is rejected
        status, body = self._request(
            "POST", "/api/users/register",
            body={"email": "hacker2@example.com", "password": "Strong1!", "company_id": 999, "company_name": "Hack Ltd 2"},
            headers={"X-Tenant-ID": "1"}
        )
        self.assertEqual(status, 400)
        self.assertIn("inquilino no coincide", body.get("error", ""))


if __name__ == "__main__":
    unittest.main()
