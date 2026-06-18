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


class BranchesCrudIsolationIntegrationTests(unittest.TestCase):
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

    def _delete(self, path: str, token: str | None) -> tuple[int, dict]:
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

    def test_branches_crud_isolation(self):
        token_a = self._token_for(user_id=self.admin_a.id, company_id=1, email=self.admin_a.email)
        token_b = self._token_for(user_id=self.admin_b.id, company_id=2, email=self.admin_b.email)

        status_create_a, body_create_a = self._post(
            "/api/admin/branches",
            {"name": "Sucursal A1", "city": "CDMX", "country": "MX"},
            token=token_a,
        )
        self.assertEqual(status_create_a, 201)
        branch_id_a = body_create_a.get("branch_id")
        self.assertIsInstance(branch_id_a, int)
        self.assertEqual(body_create_a.get("branch", {}).get("company_id"), 1)

        status_create_b, body_create_b = self._post(
            "/api/admin/branches",
            {"name": "Sucursal B1", "city": "Bogotá", "country": "CO"},
            token=token_b,
        )
        self.assertEqual(status_create_b, 201)
        branch_id_b = body_create_b.get("branch_id")
        self.assertIsInstance(branch_id_b, int)
        self.assertEqual(body_create_b.get("branch", {}).get("company_id"), 2)

        conn = self.repo._persistent_conn
        row_a = conn.execute(
            "SELECT company_id, name FROM branches WHERE company_id = 1 AND id = ?",
            (int(branch_id_a),),
        ).fetchone()
        self.assertIsNotNone(row_a)
        self.assertEqual(int(row_a[0]), 1)

        row_b = conn.execute(
            "SELECT company_id, name FROM branches WHERE company_id = 2 AND id = ?",
            (int(branch_id_b),),
        ).fetchone()
        self.assertIsNotNone(row_b)
        self.assertEqual(int(row_b[0]), 2)

        status_list_a, body_list_a = self._get("/api/admin/branches", token=token_a)
        self.assertEqual(status_list_a, 200)
        data_a = body_list_a.get("data")
        self.assertIsInstance(data_a, list)
        self.assertTrue(all(b.get("company_id") == 1 for b in data_a))
        self.assertFalse(any(b.get("company_id") == 2 for b in data_a))

        status_update_a, body_update_a = self._put(
            f"/api/admin/branches/{int(branch_id_a)}",
            {"city": "Monterrey"},
            token=token_a,
        )
        self.assertEqual(status_update_a, 200)
        self.assertEqual(body_update_a.get("branch", {}).get("company_id"), 1)
        self.assertEqual(body_update_a.get("branch", {}).get("city"), "Monterrey")
        row_a_city = conn.execute(
            "SELECT city FROM branches WHERE company_id = 1 AND id = ?",
            (int(branch_id_a),),
        ).fetchone()
        self.assertIsNotNone(row_a_city)
        self.assertEqual(str(row_a_city[0]), "Monterrey")

        row_b_before = conn.execute(
            "SELECT city, status FROM branches WHERE company_id = 2 AND id = ?",
            (int(branch_id_b),),
        ).fetchone()
        self.assertIsNotNone(row_b_before)

        status_cross, _ = self._put(f"/api/admin/branches/{int(branch_id_b)}", {"city": "Hack"}, token=token_a)
        self.assertIn(status_cross, (403, 404))
        row_b_after = conn.execute(
            "SELECT city, status FROM branches WHERE company_id = 2 AND id = ?",
            (int(branch_id_b),),
        ).fetchone()
        self.assertEqual(row_b_after, row_b_before)

        status_delete_cross, _ = self._delete(f"/api/admin/branches/{int(branch_id_b)}", token=token_a)
        self.assertIn(status_delete_cross, (403, 404))
        status_b_after_cross = conn.execute(
            "SELECT status FROM branches WHERE company_id = 2 AND id = ?",
            (int(branch_id_b),),
        ).fetchone()
        self.assertIsNotNone(status_b_after_cross)
        self.assertEqual(str(status_b_after_cross[0]), "active")

        status_delete_a, body_delete_a = self._delete(f"/api/admin/branches/{int(branch_id_a)}", token=token_a)
        self.assertEqual(status_delete_a, 200)
        self.assertIn(body_delete_a.get("changed"), (True, False))
        status_a_after = conn.execute(
            "SELECT status FROM branches WHERE company_id = 1 AND id = ?",
            (int(branch_id_a),),
        ).fetchone()
        self.assertIsNotNone(status_a_after)
        self.assertEqual(str(status_a_after[0]), "inactive")


if __name__ == "__main__":
    unittest.main()
