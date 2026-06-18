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


class PurchasesCrudIntegrationTests(unittest.TestCase):
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
        self.admin_b, _ = self.repo.create_user_with_role(
            company_id=2, email="admin-b@example.com", password_hash=password_hash_v, role_id=12
        )
        self.almacenista_a, _ = self.repo.create_user_with_role(
            company_id=1, email="alm-a@example.com", password_hash=password_hash_v, role_id=10
        )

        self.supplier_active_a = self.repo.create_supplier(
            company_id=1,
            name="Proveedor A",
            document_id="DOC-A",
            contact_email=None,
            phone=None,
            status="active",
            created_at=100,
            updated_at=100,
        )
        self.supplier_inactive_a = self.repo.create_supplier(
            company_id=1,
            name="Proveedor A Inactivo",
            document_id="DOC-A-I",
            contact_email=None,
            phone=None,
            status="inactive",
            created_at=101,
            updated_at=101,
        )
        self.supplier_active_b = self.repo.create_supplier(
            company_id=2,
            name="Proveedor B",
            document_id="DOC-B",
            contact_email=None,
            phone=None,
            status="active",
            created_at=102,
            updated_at=102,
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

    def test_create_purchase_order_rejects_nonexistent_supplier(self):
        token = self._token_for(user_id=self.admin_a.id, company_id=1, email=self.admin_a.email)
        status, body = self._post("/api/admin/purchase-orders", {"supplier_id": 999999}, token=token)
        self.assertEqual(status, 400)
        self.assertEqual(body.get("error"), "supplier_not_found")

    def test_create_purchase_order_rejects_cross_tenant_supplier(self):
        token = self._token_for(user_id=self.admin_a.id, company_id=1, email=self.admin_a.email)
        status, body = self._post(
            "/api/admin/purchase-orders",
            {"supplier_id": int(self.supplier_active_b.id)},
            token=token,
        )
        self.assertIn(status, (400, 403))
        if status == 400:
            self.assertEqual(body.get("error"), "invalid_supplier")

    def test_create_purchase_order_rejects_inactive_supplier(self):
        token = self._token_for(user_id=self.admin_a.id, company_id=1, email=self.admin_a.email)
        status, body = self._post(
            "/api/admin/purchase-orders",
            {"supplier_id": int(self.supplier_inactive_a.id)},
            token=token,
        )
        self.assertEqual(status, 400)
        self.assertEqual(body.get("error"), "invalid_supplier")

    def test_create_purchase_order_success_201(self):
        token = self._token_for(user_id=self.admin_a.id, company_id=1, email=self.admin_a.email)
        status, body = self._post(
            "/api/admin/purchase-orders",
            {"company_id": 2, "supplier_id": int(self.supplier_active_a.id)},
            token=token,
        )
        self.assertEqual(status, 201)
        po = body.get("purchase_order")
        self.assertIsInstance(po, dict)
        self.assertEqual(po.get("company_id"), 1)
        self.assertEqual(po.get("supplier_id"), int(self.supplier_active_a.id))
        self.assertIsInstance(po.get("id"), int)

        po_id = int(po["id"])
        row = self.repo._persistent_conn.execute(
            "SELECT company_id, supplier_id, status FROM purchase_orders WHERE company_id = 1 AND id = ?",
            (po_id,),
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(int(row[0]), 1)
        self.assertEqual(int(row[1]), int(self.supplier_active_a.id))
        self.assertEqual(str(row[2]), "created")

    def test_create_purchase_order_requires_permission(self):
        token = self._token_for(user_id=self.almacenista_a.id, company_id=1, email=self.almacenista_a.email)
        status, _ = self._post(
            "/api/admin/purchase-orders",
            {"supplier_id": int(self.supplier_active_a.id)},
            token=token,
        )
        self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main()
