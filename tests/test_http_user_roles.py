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


class HttpUserRolesTests(unittest.TestCase):
    def setUp(self):
        self._prev_secret = HttpApiHandler.jwt_secret
        self._prev_repo = HttpApiHandler.repo
        self._prev_exp = getattr(HttpApiHandler, "jwt_expiration_minutes", 60)

        self.repo = SqliteUserRepository(":memory:")
        HttpApiHandler.repo = self.repo
        HttpApiHandler.jwt_secret = "test-secret"
        HttpApiHandler.jwt_expiration_minutes = 60

        password_hash = hash_password("Strong1!")
        self.admin_user, _ = self.repo.create_user_with_role(
            company_id=1,
            email="admin@example.com",
            password_hash=password_hash,
            role_id=12,
        )
        self.normal_user, _ = self.repo.create_user_with_role(
            company_id=1,
            email="user@example.com",
            password_hash=password_hash,
            role_id=10,
        )
        self.other_company_user, _ = self.repo.create_user_with_role(
            company_id=2,
            email="other@example.com",
            password_hash=password_hash,
            role_id=10,
        )
        self.other_company_admin, _ = self.repo.create_user_with_role(
            company_id=2,
            email="admin2@example.com",
            password_hash=password_hash,
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

    def _post(self, path: str, body: dict, token: str | None = None) -> tuple[int, dict]:
        conn = http.client.HTTPConnection(self.base[0], self.base[1], timeout=2)
        try:
            headers = {"Content-Type": "application/json"}
            if token is not None:
                headers["Authorization"] = f"Bearer {token}"
            raw = json.dumps(body).encode("utf-8")
            conn.request("POST", path, body=raw, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, ({} if not data else json.loads(data.decode("utf-8")))
        finally:
            conn.close()

    def _get(self, path: str, token: str | None = None) -> tuple[int, dict]:
        conn = http.client.HTTPConnection(self.base[0], self.base[1], timeout=2)
        try:
            headers = {}
            if token is not None:
                headers["Authorization"] = f"Bearer {token}"
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, ({} if not data else json.loads(data.decode("utf-8")))
        finally:
            conn.close()

    def _token_for(self, *, user_id: int, company_id: int, email: str) -> str:
        return create_jwt_hs256(
            {"sub": str(user_id), "company_id": int(company_id), "email": str(email)},
            secret="test-secret",
            expires_in_seconds=60,
        )

    def test_assign_requires_auth(self):
        status, body = self._post(
            "/api/admin/user-roles/assign",
            {"company_id": 1, "user_id": self.normal_user.id, "role_id": 11},
            token=None,
        )
        self.assertEqual(status, 401)
        self.assertEqual(body.get("error"), "unauthorized")

    def test_assign_rejects_without_permissions(self):
        token = self._token_for(user_id=self.normal_user.id, company_id=1, email=self.normal_user.email)
        status, body = self._post(
            "/api/admin/user-roles/assign",
            {"company_id": 1, "user_id": self.normal_user.id, "role_id": 11},
            token=token,
        )
        self.assertEqual(status, 403)
        self.assertEqual(body.get("error"), "forbidden")

    def test_assign_and_revoke_role(self):
        token = self._token_for(user_id=self.admin_user.id, company_id=1, email=self.admin_user.email)

        status, body = self._post(
            "/api/admin/user-roles/assign",
            {"company_id": 1, "user_id": self.normal_user.id, "role_id": 11},
            token=token,
        )
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "ok")
        self.assertEqual(body.get("changed"), True)
        role_names = set(self.repo.list_user_role_names(company_id=1, user_id=self.normal_user.id))
        self.assertIn("Supervisor", role_names)

        status, body = self._post(
            "/api/admin/user-roles/revoke",
            {"company_id": 1, "user_id": self.normal_user.id, "role_id": 11},
            token=token,
        )
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "ok")
        self.assertEqual(body.get("changed"), True)
        role_names = set(self.repo.list_user_role_names(company_id=1, user_id=self.normal_user.id))
        self.assertNotIn("Supervisor", role_names)

    def test_company_isolation_rejects_cross_tenant_target_user(self):
        token = self._token_for(user_id=self.admin_user.id, company_id=1, email=self.admin_user.email)
        status, body = self._post(
            "/api/admin/user-roles/assign",
            {"company_id": 1, "user_id": self.other_company_user.id, "role_id": 11},
            token=token,
        )
        self.assertEqual(status, 404)
        self.assertEqual(body.get("error"), "not_found")

    def test_company_isolation_rejects_company_mismatch_between_token_and_payload(self):
        token = self._token_for(user_id=self.admin_user.id, company_id=1, email=self.admin_user.email)
        status, body = self._post(
            "/api/admin/user-roles/assign",
            {"company_id": 2, "user_id": self.other_company_user.id, "role_id": 11},
            token=token,
        )
        self.assertEqual(status, 403)
        self.assertEqual(body.get("error"), "forbidden")

    def test_list_roles_requires_permission(self):
        token = self._token_for(user_id=self.normal_user.id, company_id=1, email=self.normal_user.email)
        status, body = self._get("/api/admin/roles", token=token)
        self.assertEqual(status, 403)
        self.assertEqual(body.get("error"), "forbidden")

    def test_list_roles_scoped_by_token_company(self):
        token = self._token_for(user_id=self.admin_user.id, company_id=1, email=self.admin_user.email)
        status, body = self._get("/api/admin/roles", token=token)
        self.assertEqual(status, 200)
        roles = body.get("roles")
        self.assertIsInstance(roles, list)
        self.assertGreaterEqual(len(roles), 1)
        self.assertTrue(all(r.get("company_id") == 1 for r in roles))

        token2 = self._token_for(user_id=self.other_company_admin.id, company_id=2, email=self.other_company_admin.email)
        status2, body2 = self._get("/api/admin/roles", token=token2)
        self.assertEqual(status2, 200)
        roles2 = body2.get("roles")
        self.assertIsInstance(roles2, list)
        self.assertGreaterEqual(len(roles2), 1)
        self.assertTrue(all(r.get("company_id") == 2 for r in roles2))

    def test_list_permissions_returns_code_and_description(self):
        token = self._token_for(user_id=self.admin_user.id, company_id=1, email=self.admin_user.email)
        status, body = self._get("/api/admin/permissions", token=token)
        self.assertEqual(status, 200)
        perms = body.get("permissions")
        self.assertIsInstance(perms, list)
        self.assertTrue(any(p.get("code") == "roles:leer" for p in perms))
        self.assertTrue(all("code" in p and "description" in p for p in perms))

    def test_unknown_admin_endpoint_is_denied_by_default(self):
        status, body = self._get("/api/admin/unknown", token=None)
        self.assertEqual(status, 403)
        self.assertEqual(body.get("error"), "forbidden")


if __name__ == "__main__":
    unittest.main()
