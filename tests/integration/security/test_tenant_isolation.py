import http.client
import json
import os
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

from gestor_inventory.infrastructure.sqlite_user_repository import SqliteUserRepository
from gestor_inventory.presentation.http_api import HttpApiHandler
from gestor_inventory.security.jwt import create_jwt_hs256
from gestor_inventory.security.password_hash import hash_password


class TenantIsolationIntegrationTests(unittest.TestCase):
    def setUp(self):
        self._prev_secret = HttpApiHandler.jwt_secret
        self._prev_repo = HttpApiHandler.repo
        self._prev_exp = getattr(HttpApiHandler, "jwt_expiration_minutes", 60)

        self.repo = SqliteUserRepository(":memory:")
        HttpApiHandler.repo = self.repo
        HttpApiHandler.jwt_secret = "test-secret"
        HttpApiHandler.jwt_expiration_minutes = 60

        password_hash_v = hash_password("Strong1!")
        self.user_a, _ = self.repo.create_user_with_role(
            company_id=1, email="admin-a@example.com", password_hash=password_hash_v, role_id=12
        )
        self.user_b, _ = self.repo.create_user_with_role(
            company_id=2, email="admin-b@example.com", password_hash=password_hash_v, role_id=12
        )

        self.branch_a = self.repo.create_branch(company_id=1, name="Sucursal A", address=None, is_active=True)
        self.branch_b = self.repo.create_branch(company_id=2, name="Sucursal B", address=None, is_active=True)

        self.product_a = self.repo.create_product(
            company_id=1, category_id=None, sku="SKU-A", name="Prod A", description=None, is_active=True
        )
        self.product_b = self.repo.create_product(
            company_id=2, category_id=None, sku="SKU-B", name="Prod B", description=None, is_active=True
        )

        self.repo.upsert_inventory_item(
            company_id=1,
            branch_id=self.branch_a.id,
            product_id=self.product_a.id,
            quantity=10,
            min_quantity=0,
            updated_at=123,
        )
        self.repo.upsert_inventory_item(
            company_id=2,
            branch_id=self.branch_b.id,
            product_id=self.product_b.id,
            quantity=20,
            min_quantity=0,
            updated_at=456,
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

    def _get(self, path: str, token: str | None) -> tuple[int, dict]:
        conn = http.client.HTTPConnection(self.base[0], self.base[1], timeout=2)
        try:
            headers = {}
            if token is not None:
                headers["Authorization"] = f"Bearer {token}"
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            return resp.status, ({} if not raw else json.loads(raw.decode("utf-8")))
        finally:
            conn.close()

    def _post(self, path: str, body: dict, token: str | None) -> tuple[int, dict]:
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

    def test_read_isolation_inventory_list(self):
        token_a = self._token_for(user_id=self.user_a.id, company_id=1, email=self.user_a.email)
        status, body = self._get(f"/api/inventory?branch_id={self.branch_a.id}", token=token_a)
        self.assertEqual(status, 200)
        items = body.get("items")
        self.assertIsInstance(items, list)
        self.assertTrue(all(i.get("company_id") == 1 for i in items))
        self.assertTrue(all(i.get("branch_id") == self.branch_a.id for i in items))
        self.assertFalse(any(i.get("product_id") == self.product_b.id for i in items))

    def test_read_isolation_roles_list(self):
        token_a = self._token_for(user_id=self.user_a.id, company_id=1, email=self.user_a.email)
        status, body = self._get("/api/admin/roles", token=token_a)
        self.assertEqual(status, 200)
        roles = body.get("roles")
        self.assertIsInstance(roles, list)
        self.assertTrue(all(r.get("company_id") == 1 for r in roles))

    def test_direct_access_isolation_category_by_id(self):
        category_b = self.repo.create_category(company_id=2, name="Cat B", is_active=True)
        token_a = self._token_for(user_id=self.user_a.id, company_id=1, email=self.user_a.email)
        status, body = self._get(f"/api/admin/categories/{category_b.id}", token=token_a)
        self.assertIn(status, (403, 404))
        if status == 404:
            self.assertEqual(body.get("error"), "not_found")

    def test_cross_tenant_write_rejected_on_product_create(self):
        category_b = self.repo.create_category(company_id=2, name="Cat B2", is_active=True)
        token_a = self._token_for(user_id=self.user_a.id, company_id=1, email=self.user_a.email)
        status, body = self._post(
            "/api/admin/products",
            {"sku": "SKU-CT", "name": "Prod CT", "category_id": category_b.id},
            token=token_a,
        )
        self.assertIn(status, (400, 403))
        if status == 400:
            self.assertEqual(body.get("error"), "validation_error")

        row = self.repo._persistent_conn.execute("SELECT 1 FROM products WHERE sku = ? LIMIT 1", ("SKU-CT",)).fetchone()
        self.assertIsNone(row)

    def test_read_isolation_list_branches(self):
        token_a = self._token_for(user_id=self.user_a.id, company_id=1, email=self.user_a.email)
        status, body = self._get("/api/admin/branches", token=token_a)
        self.assertEqual(status, 200)
        data = body.get("data")
        self.assertIsInstance(data, list)
        self.assertTrue(all(b.get("company_id") == 1 for b in data))
        self.assertFalse(any(b.get("company_id") == 2 for b in data))

    def test_list_branches_filters_city_and_status(self):
        conn = self.repo._persistent_conn
        conn.execute("UPDATE branches SET city = 'Monterrey', status = 'active' WHERE company_id = 1 AND id = ?", (self.branch_a.id,))
        self.repo.create_branch(
            company_id=1,
            name="Sucursal Inactiva",
            address=None,
            city="CDMX",
            country=None,
            status="inactive",
            is_active=False,
        )
        self.repo.create_branch(
            company_id=1,
            name="Sucursal Extra",
            address=None,
            city="CDMX",
            country=None,
            status="active",
            is_active=True,
        )
        conn.commit()

        token_a = self._token_for(user_id=self.user_a.id, company_id=1, email=self.user_a.email)

        status_city, body_city = self._get("/api/admin/branches?city=Monterrey", token=token_a)
        self.assertEqual(status_city, 200)
        self.assertTrue(all(b.get("city") == "Monterrey" for b in body_city.get("data") or []))

        status_inactive, body_inactive = self._get("/api/admin/branches?status=inactive", token=token_a)
        self.assertEqual(status_inactive, 200)
        self.assertTrue(all(b.get("status") == "inactive" for b in body_inactive.get("data") or []))

        status_combo, body_combo = self._get("/api/admin/branches?city=CDMX&status=active", token=token_a)
        self.assertEqual(status_combo, 200)
        self.assertTrue(all(b.get("city") == "CDMX" and b.get("status") == "active" for b in body_combo.get("data") or []))


if __name__ == "__main__":
    unittest.main()
