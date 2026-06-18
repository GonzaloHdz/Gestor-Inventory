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


class CompanySettingsIsolationIntegrationTests(unittest.TestCase):
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
            company_id=1, email="admin-a-settings@example.com", password_hash=password_hash_v, role_id=12
        )
        self.admin_b, _ = self.repo.create_user_with_role(
            company_id=2, email="admin-b-settings@example.com", password_hash=password_hash_v, role_id=12
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

    def test_settings_upsert_and_isolation(self):
        token_a = self._token_for(user_id=self.admin_a.id, company_id=1, email=self.admin_a.email)
        token_b = self._token_for(user_id=self.admin_b.id, company_id=2, email=self.admin_b.email)

        status_empty, body_empty = self._get("/api/admin/settings", token=token_a)
        self.assertEqual(status_empty, 200)
        self.assertEqual(body_empty.get("data"), [])

        status_put_a, _ = self._put(
            "/api/admin/settings",
            {"stock_minimo": "10", "notificaciones_activas": "true"},
            token=token_a,
        )
        self.assertEqual(status_put_a, 200)

        conn = self.repo._persistent_conn
        row_count = conn.execute(
            "SELECT COUNT(1) FROM company_settings WHERE company_id = 1 AND setting_key = ?",
            ("stock_minimo",),
        ).fetchone()
        self.assertIsNotNone(row_count)
        self.assertEqual(int(row_count[0]), 1)

        status_get_a, body_get_a = self._get("/api/admin/settings", token=token_a)
        self.assertEqual(status_get_a, 200)
        data_a = body_get_a.get("data") or []
        self.assertTrue(all(isinstance(x, dict) for x in data_a))
        self.assertTrue(any(x.get("key") == "stock_minimo" and x.get("value") == "10" for x in data_a))

        status_get_b_empty, body_get_b_empty = self._get("/api/admin/settings", token=token_b)
        self.assertEqual(status_get_b_empty, 200)
        self.assertEqual(body_get_b_empty.get("data"), [])

        status_put_b, _ = self._put("/api/admin/settings", {"stock_minimo": "999"}, token=token_b)
        self.assertEqual(status_put_b, 200)

        status_get_a_again, body_get_a_again = self._get("/api/admin/settings", token=token_a)
        self.assertEqual(status_get_a_again, 200)
        data_a_again = body_get_a_again.get("data") or []
        self.assertTrue(any(x.get("key") == "stock_minimo" and x.get("value") == "10" for x in data_a_again))

        row_a = conn.execute(
            "SELECT setting_value FROM company_settings WHERE company_id = 1 AND setting_key = ?",
            ("stock_minimo",),
        ).fetchone()
        row_b = conn.execute(
            "SELECT setting_value FROM company_settings WHERE company_id = 2 AND setting_key = ?",
            ("stock_minimo",),
        ).fetchone()
        self.assertEqual(str(row_a[0]), "10")
        self.assertEqual(str(row_b[0]), "999")

        logs = conn.execute(
            "SELECT company_id, user_id, action, resource FROM audit_logs WHERE resource = ? ORDER BY id",
            ("configuracion",),
        ).fetchall()
        self.assertTrue(any(int(c) == 1 and int(u) == self.admin_a.id and str(a) == "UPDATE" for (c, u, a, _) in logs))

    def test_settings_validation_rejects_unknown_key(self):
        token_a = self._token_for(user_id=self.admin_a.id, company_id=1, email=self.admin_a.email)
        status, body = self._put("/api/admin/settings", {"llave_falsa": "123"}, token=token_a)
        self.assertEqual(status, 400)
        self.assertEqual(body.get("error"), "validation_error")
        self.assertIn("llave_falsa", str(body.get("message", "")))

    def test_settings_validation_rejects_invalid_value(self):
        token_a = self._token_for(user_id=self.admin_a.id, company_id=1, email=self.admin_a.email)
        status, body = self._put("/api/admin/settings", {"stock_minimo": "letras"}, token=token_a)
        self.assertEqual(status, 400)
        self.assertEqual(body.get("error"), "validation_error")
        self.assertIn("stock_minimo", str(body.get("message", "")))

    def test_settings_validation_accepts_known_keys(self):
        token_a = self._token_for(user_id=self.admin_a.id, company_id=1, email=self.admin_a.email)
        status, _ = self._put(
            "/api/admin/settings",
            {"moneda": "mxn", "stock_minimo": 5, "notificaciones_activas": False},
            token=token_a,
        )
        self.assertEqual(status, 200)

        conn = self.repo._persistent_conn
        moneda = conn.execute(
            "SELECT setting_value FROM company_settings WHERE company_id = 1 AND setting_key = ?",
            ("moneda",),
        ).fetchone()
        stock_minimo = conn.execute(
            "SELECT setting_value FROM company_settings WHERE company_id = 1 AND setting_key = ?",
            ("stock_minimo",),
        ).fetchone()
        notificaciones = conn.execute(
            "SELECT setting_value FROM company_settings WHERE company_id = 1 AND setting_key = ?",
            ("notificaciones_activas",),
        ).fetchone()
        self.assertEqual(str(moneda[0]), "MXN")
        self.assertEqual(str(stock_minimo[0]), "5")
        self.assertEqual(str(notificaciones[0]), "false")


if __name__ == "__main__":
    unittest.main()
