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


class SuppliersCrudIntegrationTests(unittest.TestCase):
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

    def _data_audit_logs(self) -> list[dict]:
        conn = self.repo._persistent_conn
        rows = conn.execute(
            "SELECT company_id, user_id, action, resource, details FROM audit_logs ORDER BY id"
        ).fetchall()
        return [
            {"company_id": int(c), "user_id": int(u), "action": str(a), "resource": str(r), "details": d}
            for (c, u, a, r, d) in rows
        ]

    def test_create_supplier_success_201_and_company_injected(self):
        token = self._token_for(user_id=self.admin_a.id, company_id=1, email=self.admin_a.email)
        status, body = self._post(
            "/api/admin/suppliers",
            {
                "company_id": 2,
                "name": "Proveedor 1",
                "document_id": "DOC-1",
                "contact_email": "p1@example.com",
                "phone": "123",
            },
            token=token,
        )
        self.assertEqual(status, 201)
        supplier = body.get("supplier")
        self.assertIsInstance(supplier, dict)
        self.assertEqual(supplier.get("company_id"), 1)
        self.assertIsInstance(supplier.get("id"), int)
        self.assertEqual(supplier.get("status"), "active")

        supplier_id = int(supplier["id"])
        row = self.repo._persistent_conn.execute(
            "SELECT company_id, name, document_id, status FROM suppliers WHERE company_id = 1 AND id = ?",
            (supplier_id,),
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(int(row[0]), 1)
        self.assertEqual(str(row[1]), "Proveedor 1")
        self.assertEqual(str(row[2]), "DOC-1")
        self.assertEqual(str(row[3]), "active")

        logs = self._data_audit_logs()
        self.assertTrue(
            any(
                l["company_id"] == 1
                and l["user_id"] == self.admin_a.id
                and l["action"] == "CREATE"
                and l["resource"] == "proveedores"
                for l in logs
            )
        )

    def test_create_supplier_requires_permission(self):
        token = self._token_for(user_id=self.almacenista_a.id, company_id=1, email=self.almacenista_a.email)
        status, _ = self._post("/api/admin/suppliers", {"name": "Proveedor X"}, token=token)
        self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main()
