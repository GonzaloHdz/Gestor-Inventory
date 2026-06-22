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
        self.superadmin_user, _ = self.repo.create_user_with_role(
            company_id=1,
            email="superadmin@example.com",
            password_hash=password_hash,
            role_id=13,
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

    def _put(self, path: str, body: dict, token: str | None = None) -> tuple[int, dict]:
        conn = http.client.HTTPConnection(self.base[0], self.base[1], timeout=2)
        try:
            headers = {"Content-Type": "application/json"}
            if token is not None:
                headers["Authorization"] = f"Bearer {token}"
            raw = json.dumps(body).encode("utf-8")
            conn.request("PUT", path, body=raw, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, ({} if not data else json.loads(data.decode("utf-8")))
        finally:
            conn.close()

    def _patch(self, path: str, body: dict, token: str | None = None) -> tuple[int, dict]:
        conn = http.client.HTTPConnection(self.base[0], self.base[1], timeout=2)
        try:
            headers = {"Content-Type": "application/json"}
            if token is not None:
                headers["Authorization"] = f"Bearer {token}"
            raw = json.dumps(body).encode("utf-8")
            conn.request("PATCH", path, body=raw, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, ({} if not data else json.loads(data.decode("utf-8")))
        finally:
            conn.close()

    def _delete(self, path: str, token: str | None = None) -> tuple[int, dict]:
        conn = http.client.HTTPConnection(self.base[0], self.base[1], timeout=2)
        try:
            headers = {}
            if token is not None:
                headers["Authorization"] = f"Bearer {token}"
            conn.request("DELETE", path, headers=headers)
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

    def test_create_internal_user_requires_auth(self):
        status, body = self._post(
            "/api/admin/users",
            {"email": "nuevo@example.com", "password": "Secret1!", "role_id": 10},
            token=None,
        )
        self.assertEqual(status, 401)
        self.assertEqual(body.get("error"), "unauthorized")

    def test_create_internal_user_rejects_without_permissions(self):
        token = self._token_for(user_id=self.normal_user.id, company_id=1, email=self.normal_user.email)
        status, body = self._post(
            "/api/admin/users",
            {"email": "nuevo@example.com", "password": "Secret1!", "role_id": 10},
            token=token,
        )
        self.assertEqual(status, 403)
        self.assertEqual(body.get("error"), "forbidden")

    def test_create_internal_user_creates_user_in_actor_company(self):
        token = self._token_for(user_id=self.admin_user.id, company_id=1, email=self.admin_user.email)
        status, body = self._post(
            "/api/admin/users",
            {
                "company_id": 2,
                "email": "nuevo@example.com",
                "password": "Secret1!",
                "role_id": 10,
            },
            token=token,
        )
        self.assertEqual(status, 201)
        user = body.get("user", {})
        self.assertEqual(user.get("company_id"), 1)
        self.assertEqual(user.get("email"), "nuevo@example.com")
        self.assertEqual(user.get("role_id"), 10)
        self.assertFalse(user.get("verified"))
        self.assertIn("verification_url", body)

        created_user_id = user.get("id")
        self.assertIsInstance(created_user_id, int)
        role_names = set(self.repo.list_user_role_names(company_id=1, user_id=created_user_id))
        self.assertIn("Almacenista", role_names)

    def test_admin_cannot_create_superadmin_user(self):
        token = self._token_for(user_id=self.admin_user.id, company_id=1, email=self.admin_user.email)
        status, body = self._post(
            "/api/admin/users",
            {"email": "supernuevo@example.com", "password": "Secret1!", "role_id": 13},
            token=token,
        )
        self.assertEqual(status, 403)
        self.assertEqual(body.get("error"), "forbidden")

    def test_superadmin_can_create_superadmin_user(self):
        token = self._token_for(
            user_id=self.other_company_admin.id,
            company_id=2,
            email=self.other_company_admin.email,
        )
        self.repo.assign_role_to_user(company_id=2, user_id=self.other_company_admin.id, role_id=13)
        status, body = self._post(
            "/api/admin/users",
            {"email": "super2@example.com", "password": "Secret1!", "role_id": 13},
            token=token,
        )
        self.assertEqual(status, 201)
        user = body.get("user", {})
        self.assertEqual(user.get("company_id"), 2)
        self.assertEqual(user.get("role_id"), 13)

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

    def test_assign_rejects_self_escalation(self):
        token = self._token_for(user_id=self.admin_user.id, company_id=1, email=self.admin_user.email)
        status, body = self._post(
            "/api/admin/user-roles/assign",
            {"company_id": 1, "user_id": self.admin_user.id, "role_id": 13},
            token=token,
        )
        self.assertEqual(status, 403)
        self.assertEqual(body.get("error"), "forbidden")

    def test_admin_cannot_assign_superadmin_role(self):
        token = self._token_for(user_id=self.admin_user.id, company_id=1, email=self.admin_user.email)
        status, body = self._post(
            "/api/admin/user-roles/assign",
            {"company_id": 1, "user_id": self.normal_user.id, "role_id": 13},
            token=token,
        )
        self.assertEqual(status, 403)
        self.assertEqual(body.get("error"), "forbidden")

    def test_admin_cannot_modify_superadmin_roles(self):
        token = self._token_for(user_id=self.admin_user.id, company_id=1, email=self.admin_user.email)
        status, body = self._post(
            "/api/admin/user-roles/revoke",
            {"company_id": 1, "user_id": self.superadmin_user.id, "role_id": 13},
            token=token,
        )
        self.assertEqual(status, 403)
        self.assertEqual(body.get("error"), "forbidden")

    def test_superadmin_can_assign_and_revoke_superadmin_role(self):
        token = self._token_for(user_id=self.superadmin_user.id, company_id=1, email=self.superadmin_user.email)
        status_assign, body_assign = self._post(
            "/api/admin/user-roles/assign",
            {"company_id": 1, "user_id": self.normal_user.id, "role_id": 13},
            token=token,
        )
        self.assertEqual(status_assign, 200)
        self.assertEqual(body_assign.get("changed"), True)
        self.assertIn("Superadministrador", set(self.repo.list_user_role_names(company_id=1, user_id=self.normal_user.id)))

        status_revoke, body_revoke = self._post(
            "/api/admin/user-roles/revoke",
            {"company_id": 1, "user_id": self.normal_user.id, "role_id": 13},
            token=token,
        )
        self.assertEqual(status_revoke, 200)
        self.assertEqual(body_revoke.get("changed"), True)
        self.assertNotIn("Superadministrador", set(self.repo.list_user_role_names(company_id=1, user_id=self.normal_user.id)))

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

    def test_list_users_requires_auth(self):
        status, body = self._get("/api/users", token=None)
        self.assertEqual(status, 401)
        self.assertEqual(body.get("error"), "unauthorized")

    def test_list_users_requires_permission(self):
        token = self._token_for(user_id=self.normal_user.id, company_id=1, email=self.normal_user.email)
        status, body = self._get("/api/users", token=token)
        self.assertEqual(status, 403)
        self.assertEqual(body.get("error"), "forbidden")

    def test_list_users_scoped_by_token_company(self):
        token = self._token_for(user_id=self.admin_user.id, company_id=1, email=self.admin_user.email)
        status, body = self._get("/api/users?page=1&per_page=10", token=token)
        self.assertEqual(status, 200)
        data = body.get("data")
        self.assertIsInstance(data, list)
        self.assertTrue(all(item.get("company_id") == 1 for item in data))
        emails = {item.get("email") for item in data}
        self.assertIn("admin@example.com", emails)
        self.assertIn("user@example.com", emails)
        self.assertIn("superadmin@example.com", emails)
        self.assertNotIn("other@example.com", emails)
        self.assertTrue(any("Administrador" in item.get("roles", []) for item in data if item.get("email") == "admin@example.com"))

    def test_list_users_paginates(self):
        token = self._token_for(user_id=self.admin_user.id, company_id=1, email=self.admin_user.email)
        for idx in range(3):
            self.repo.create_user_with_role(
                company_id=1,
                email=f"extra{idx}@example.com",
                password_hash=hash_password("Strong1!"),
                role_id=10,
            )

        status, body = self._get("/api/users?page=1&per_page=2", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(len(body.get("data", [])), 2)
        pagination = body.get("pagination", {})
        self.assertEqual(pagination.get("page"), 1)
        self.assertEqual(pagination.get("per_page"), 2)
        self.assertGreaterEqual(pagination.get("total"), 6)
        self.assertGreaterEqual(pagination.get("pages"), 3)

    def test_get_user_by_id_requires_permission_and_is_tenant_scoped(self):
        token_user = self._token_for(user_id=self.normal_user.id, company_id=1, email=self.normal_user.email)
        status_forbidden, body_forbidden = self._get(f"/api/users/{self.normal_user.id}", token=token_user)
        self.assertEqual(status_forbidden, 403)
        self.assertEqual(body_forbidden.get("error"), "forbidden")

        token_admin = self._token_for(user_id=self.admin_user.id, company_id=1, email=self.admin_user.email)
        status_ok, body_ok = self._get(f"/api/users/{self.normal_user.id}", token=token_admin)
        self.assertEqual(status_ok, 200)
        user = body_ok.get("user", {})
        self.assertEqual(user.get("id"), self.normal_user.id)
        self.assertEqual(user.get("company_id"), 1)
        self.assertEqual(user.get("email"), "user@example.com")
        self.assertIn("Almacenista", user.get("roles", []))

        status_missing, body_missing = self._get(f"/api/users/{self.other_company_user.id}", token=token_admin)
        self.assertEqual(status_missing, 404)
        self.assertEqual(body_missing.get("error"), "not_found")

    def test_create_internal_user_supported_on_api_users(self):
        token = self._token_for(user_id=self.admin_user.id, company_id=1, email=self.admin_user.email)
        status, body = self._post(
            "/api/users",
            {"email": "crud-create@example.com", "password": "Secret1!", "role_id": 10},
            token=token,
        )
        self.assertEqual(status, 201)
        user = body.get("user", {})
        self.assertEqual(user.get("company_id"), 1)
        self.assertEqual(user.get("email"), "crud-create@example.com")
        self.assertEqual(user.get("role_id"), 10)

    def test_update_user_edits_controlled_fields(self):
        token = self._token_for(user_id=self.admin_user.id, company_id=1, email=self.admin_user.email)
        before = self.repo.get_user_by_id(company_id=1, user_id=self.normal_user.id)
        self.assertIsNotNone(before)

        status, body = self._patch(
            f"/api/users/{self.normal_user.id}",
            {
                "email": "updated-user@example.com",
                "password": "NewSecret1!",
                "is_active": False,
                "verified": True,
            },
            token=token,
        )
        self.assertEqual(status, 200)
        user = body.get("user", {})
        self.assertEqual(user.get("id"), self.normal_user.id)
        self.assertEqual(user.get("company_id"), 1)
        self.assertEqual(user.get("email"), "updated-user@example.com")
        self.assertEqual(user.get("is_active"), False)
        self.assertEqual(user.get("verified"), True)

        after = self.repo.get_user_by_id(company_id=1, user_id=self.normal_user.id)
        self.assertIsNotNone(after)
        self.assertEqual(after.email, "updated-user@example.com")
        self.assertFalse(after.is_active)
        self.assertTrue(after.verified)
        self.assertNotEqual(after.password_hash, before.password_hash)

    def test_update_user_rejects_immutable_fields_and_cross_tenant_target(self):
        token = self._token_for(user_id=self.admin_user.id, company_id=1, email=self.admin_user.email)

        status_bad, body_bad = self._put(
            f"/api/users/{self.normal_user.id}",
            {"company_id": 2, "email": "should-fail@example.com"},
            token=token,
        )
        self.assertEqual(status_bad, 400)
        self.assertEqual(body_bad.get("error"), "validation_error")

        status_missing, body_missing = self._patch(
            f"/api/users/{self.other_company_user.id}",
            {"email": "should-not-work@example.com"},
            token=token,
        )
        self.assertEqual(status_missing, 404)
        self.assertEqual(body_missing.get("error"), "not_found")

    def test_delete_user_soft_deactivates_and_rejects_self_delete(self):
        token = self._token_for(user_id=self.admin_user.id, company_id=1, email=self.admin_user.email)

        status, body = self._delete(f"/api/users/{self.normal_user.id}", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "ok")
        self.assertEqual(body.get("changed"), True)

        deactivated = self.repo.get_user_by_id(company_id=1, user_id=self.normal_user.id)
        self.assertIsNotNone(deactivated)
        self.assertFalse(deactivated.is_active)

        status_self, body_self = self._delete(f"/api/users/{self.admin_user.id}", token=token)
        self.assertEqual(status_self, 403)
        self.assertEqual(body_self.get("error"), "forbidden")

    def test_admin_cannot_update_or_delete_superadmin(self):
        token = self._token_for(user_id=self.admin_user.id, company_id=1, email=self.admin_user.email)

        status_update, body_update = self._patch(
            f"/api/users/{self.superadmin_user.id}",
            {"verified": True},
            token=token,
        )
        self.assertEqual(status_update, 403)
        self.assertEqual(body_update.get("error"), "forbidden")

        status_delete, body_delete = self._delete(f"/api/users/{self.superadmin_user.id}", token=token)
        self.assertEqual(status_delete, 403)
        self.assertEqual(body_delete.get("error"), "forbidden")

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
