import http.client
import json
import os
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

from gestor_inventory.infrastructure.sqlite_user_repository import SqliteUserRepository
from gestor_inventory.presentation.http_api import HttpApiHandler
from gestor_inventory.security.jwt import create_jwt_hs256
from gestor_inventory.security.password_hash import hash_password


class CategoriesHttpIntegrationTests(unittest.TestCase):
    def setUp(self):
        self._prev_secret = HttpApiHandler.jwt_secret
        self._prev_repo = HttpApiHandler.repo
        self._prev_exp = getattr(HttpApiHandler, "jwt_expiration_minutes", 60)

        self.repo = SqliteUserRepository(":memory:")
        HttpApiHandler.repo = self.repo
        HttpApiHandler.jwt_secret = "test-secret"
        HttpApiHandler.jwt_expiration_minutes = 60

        password_hash_v = hash_password("Strong1!")
        self.admin_a, _ = self.repo.create_user_with_role(
            company_id=1, email="admin-a-cat@example.com", password_hash=password_hash_v, role_id=12
        )
        self.almacenista_a, _ = self.repo.create_user_with_role(
            company_id=1, email="alm-a-cat@example.com", password_hash=password_hash_v, role_id=10
        )
        self.admin_b, _ = self.repo.create_user_with_role(
            company_id=2, email="admin-b-cat@example.com", password_hash=password_hash_v, role_id=12
        )

        self.cat_a_active = self.repo.create_category(company_id=1, name="Cat A Active", status="active")
        self.cat_a_inactive = self.repo.create_category(company_id=1, name="Cat A Inactive", status="inactive")
        self.cat_b_active = self.repo.create_category(company_id=2, name="Cat B Active", status="active")

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

    def _get(self, path: str, token: str | None) -> tuple[int, dict]:
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

    def _data_audit_logs(self) -> list[dict]:
        rows = self.repo._persistent_conn.execute(
            "SELECT company_id, user_id, action, resource, details FROM audit_logs ORDER BY id"
        ).fetchall()
        return [
            {"company_id": int(c), "user_id": int(u), "action": str(a), "resource": str(r), "details": d}
            for (c, u, a, r, d) in rows
        ]

    def test_list_categories_default_active_200(self):
        token = self._token_for(user_id=self.admin_a.id, company_id=1, email=self.admin_a.email)
        status, body = self._get("/api/admin/categories", token=token)
        self.assertEqual(status, 200)
        data = body.get("data")
        self.assertIsInstance(data, list)
        ids = {int(r.get("id")) for r in data if isinstance(r.get("id"), int)}
        self.assertIn(int(self.cat_a_active.id), ids)
        self.assertNotIn(int(self.cat_a_inactive.id), ids)
        self.assertNotIn(int(self.cat_b_active.id), ids)
        self.assertTrue(all(r.get("company_id") == 1 for r in data))

        logs = self._data_audit_logs()
        self.assertTrue(
            any(
                l["company_id"] == 1 and l["user_id"] == self.admin_a.id and l["action"] == "READ" and l["resource"] == "categorias"
                for l in logs
            )
        )

    def test_list_categories_status_inactive_and_all(self):
        token = self._token_for(user_id=self.admin_a.id, company_id=1, email=self.admin_a.email)
        status_inactive, body_inactive = self._get("/api/admin/categories?status=inactive", token=token)
        self.assertEqual(status_inactive, 200)
        data_inactive = body_inactive.get("data")
        self.assertIsInstance(data_inactive, list)
        ids_inactive = {int(r.get("id")) for r in data_inactive if isinstance(r.get("id"), int)}
        self.assertIn(int(self.cat_a_inactive.id), ids_inactive)
        self.assertNotIn(int(self.cat_a_active.id), ids_inactive)

        status_all, body_all = self._get("/api/admin/categories?status=all", token=token)
        self.assertEqual(status_all, 200)
        data_all = body_all.get("data")
        self.assertIsInstance(data_all, list)
        ids_all = {int(r.get("id")) for r in data_all if isinstance(r.get("id"), int)}
        self.assertIn(int(self.cat_a_active.id), ids_all)
        self.assertIn(int(self.cat_a_inactive.id), ids_all)
        self.assertNotIn(int(self.cat_b_active.id), ids_all)

    def test_list_categories_isolated_by_company_id(self):
        token_b = self._token_for(user_id=self.admin_b.id, company_id=2, email=self.admin_b.email)
        status, body = self._get("/api/admin/categories?status=all", token=token_b)
        self.assertEqual(status, 200)
        data = body.get("data")
        self.assertIsInstance(data, list)
        self.assertTrue(all(r.get("company_id") == 2 for r in data))
        self.assertTrue(any(int(r.get("id")) == int(self.cat_b_active.id) for r in data if isinstance(r.get("id"), int)))
        self.assertFalse(any(int(r.get("id")) == int(self.cat_a_active.id) for r in data if isinstance(r.get("id"), int)))

    def test_list_categories_requires_permission_403(self):
        token = self._token_for(user_id=self.almacenista_a.id, company_id=1, email=self.almacenista_a.email)
        status, _ = self._get("/api/admin/categories", token=token)
        self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main()

