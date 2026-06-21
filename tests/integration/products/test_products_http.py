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


class ProductsHttpIntegrationTests(unittest.TestCase):
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
            company_id=1, email="admin-a@example.com", password_hash=password_hash_v, role_id=12
        )
        self.almacenista_a, _ = self.repo.create_user_with_role(
            company_id=1, email="alm-a@example.com", password_hash=password_hash_v, role_id=10
        )
        self.admin_b, _ = self.repo.create_user_with_role(
            company_id=2, email="admin-b@example.com", password_hash=password_hash_v, role_id=12
        )

        self.category_a = self.repo.create_category(company_id=1, name="Cat A HTTP", is_active=True)
        self.category_b = self.repo.create_category(company_id=2, name="Cat B HTTP", is_active=True)

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

    def _put(self, path: str, body: dict, token: str | None) -> tuple[int, dict]:
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

    def test_post_product_success_201(self):
        token = self._token_for(user_id=self.admin_a.id, company_id=1, email=self.admin_a.email)
        status, body = self._post(
            "/api/admin/products",
            {
                "company_id": 2,
                "sku": "SKU-HTTP-1",
                "name": "Producto HTTP 1",
                "category_id": int(self.category_a.id),
                "stock_minimum": 2,
                "status": "active",
            },
            token=token,
        )
        self.assertEqual(status, 201)
        p = body.get("product")
        self.assertIsInstance(p, dict)
        self.assertEqual(p.get("company_id"), 1)
        self.assertEqual(p.get("sku"), "SKU-HTTP-1")
        self.assertEqual(p.get("category_id"), int(self.category_a.id))
        self.assertEqual(p.get("stock_minimum"), 2)
        self.assertEqual(p.get("status"), "active")
        self.assertIsInstance(p.get("id"), int)

        row = self.repo._persistent_conn.execute(
            "SELECT company_id, sku FROM products WHERE company_id = 1 AND sku = ? LIMIT 1",
            ("SKU-HTTP-1",),
        ).fetchone()
        self.assertIsNotNone(row)

    def test_post_product_duplicate_sku_returns_400(self):
        token = self._token_for(user_id=self.admin_a.id, company_id=1, email=self.admin_a.email)
        self._post(
            "/api/admin/products",
            {"sku": "SKU-DUP", "name": "P1", "category_id": int(self.category_a.id)},
            token=token,
        )
        status, body = self._post(
            "/api/admin/products",
            {"sku": "SKU-DUP", "name": "P2", "category_id": int(self.category_a.id)},
            token=token,
        )
        self.assertEqual(status, 400)
        self.assertEqual(body.get("error"), "duplicate_product_code")
        self.assertEqual(
            body.get("message"),
            "Ya existe un producto registrado con este SKU o código en tu empresa. Por favor, utiliza uno diferente.",
        )

    def test_post_product_cross_tenant_category_returns_400(self):
        token = self._token_for(user_id=self.admin_a.id, company_id=1, email=self.admin_a.email)
        status, body = self._post(
            "/api/admin/products",
            {"sku": "SKU-XT", "name": "XT", "category_id": int(self.category_b.id)},
            token=token,
        )
        self.assertEqual(status, 400)
        self.assertEqual(body.get("error"), "invalid_category")

    def test_post_product_requires_permission_403(self):
        token = self._token_for(user_id=self.almacenista_a.id, company_id=1, email=self.almacenista_a.email)
        status, _ = self._post(
            "/api/admin/products",
            {"sku": "SKU-NO", "name": "No", "category_id": int(self.category_a.id)},
            token=token,
        )
        self.assertEqual(status, 403)

    def test_put_product_update_name_and_stock_success_200(self):
        p = self.repo.create_product(
            company_id=1,
            category_id=int(self.category_a.id),
            sku="SKU-UP-1",
            name="Antes",
            description=None,
            stock_minimum=1,
            status="active",
        )
        token = self._token_for(user_id=self.admin_a.id, company_id=1, email=self.admin_a.email)
        status, body = self._put(
            f"/api/admin/products/{int(p.id)}",
            {"name": "Después", "stock_minimum": 5},
            token=token,
        )
        self.assertEqual(status, 200)
        updated = body.get("product")
        self.assertIsInstance(updated, dict)
        self.assertEqual(updated.get("id"), int(p.id))
        self.assertEqual(updated.get("company_id"), 1)
        self.assertEqual(updated.get("name"), "Después")
        self.assertEqual(updated.get("stock_minimum"), 5)

    def test_put_product_same_sku_success_200(self):
        p = self.repo.create_product(
            company_id=1,
            category_id=int(self.category_a.id),
            sku="SKU-UP-SAME",
            name="P",
            description=None,
            stock_minimum=0,
            status="active",
        )
        token = self._token_for(user_id=self.admin_a.id, company_id=1, email=self.admin_a.email)
        status, body = self._put(
            f"/api/admin/products/{int(p.id)}",
            {"sku": "SKU-UP-SAME"},
            token=token,
        )
        self.assertEqual(status, 200)
        self.assertEqual(body.get("product", {}).get("sku"), "SKU-UP-SAME")

    def test_put_product_duplicate_sku_returns_400(self):
        p1 = self.repo.create_product(
            company_id=1,
            category_id=int(self.category_a.id),
            sku="SKU-UP-DUP-1",
            name="P1",
            description=None,
            stock_minimum=0,
            status="active",
        )
        self.repo.create_product(
            company_id=1,
            category_id=int(self.category_a.id),
            sku="SKU-UP-DUP-2",
            name="P2",
            description=None,
            stock_minimum=0,
            status="active",
        )
        token = self._token_for(user_id=self.admin_a.id, company_id=1, email=self.admin_a.email)
        status, body = self._put(
            f"/api/admin/products/{int(p1.id)}",
            {"sku": "SKU-UP-DUP-2"},
            token=token,
        )
        self.assertEqual(status, 400)
        self.assertEqual(body.get("error"), "duplicate_product_code")
        self.assertEqual(
            body.get("message"),
            "Ya existe un producto registrado con este SKU o código en tu empresa. Por favor, utiliza uno diferente.",
        )

    def test_put_product_cross_tenant_product_returns_404_or_403(self):
        p_other = self.repo.create_product(
            company_id=2,
            category_id=int(self.category_b.id),
            sku="SKU-UP-XT",
            name="OTRO",
            description=None,
            stock_minimum=0,
            status="active",
        )
        token = self._token_for(user_id=self.admin_a.id, company_id=1, email=self.admin_a.email)
        status, _ = self._put(
            f"/api/admin/products/{int(p_other.id)}",
            {"name": "X"},
            token=token,
        )
        self.assertIn(status, (403, 404))


if __name__ == "__main__":
    unittest.main()
