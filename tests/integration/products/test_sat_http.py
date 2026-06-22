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

from gestor_inventory.infrastructure.sqlite_sat_repository import SqliteSatRepository
from gestor_inventory.presentation.http_api import HttpApiHandler
from gestor_inventory.security.jwt import create_jwt_hs256
from gestor_inventory.security.password_hash import hash_password


class SatHttpIntegrationTests(unittest.TestCase):
    def setUp(self):
        self._prev_secret = HttpApiHandler.jwt_secret
        self._prev_repo = HttpApiHandler.repo
        self._prev_exp = getattr(HttpApiHandler, "jwt_expiration_minutes", 60)

        self.repo = SqliteSatRepository(":memory:")
        HttpApiHandler.repo = self.repo
        HttpApiHandler.jwt_secret = "test-secret"
        HttpApiHandler.jwt_expiration_minutes = 60

        password_hash_v = hash_password("Strong1!")
        self.admin, _ = self.repo.create_user_with_role(
            company_id=1, email="admin@example.com", password_hash=password_hash_v, role_id=12
        )
        self.almacenista, _ = self.repo.create_user_with_role(
            company_id=1, email="almacen@example.com", password_hash=password_hash_v, role_id=10
        )
        self.repo._persistent_conn.executemany(
            "INSERT OR IGNORE INTO sat_regimenes (clave, descripcion) VALUES (?, ?)",
            [("601", "General"), ("603", "Sin fines")],
        )
        self.repo._persistent_conn.executemany(
            "INSERT OR IGNORE INTO sat_unidades (clave, nombre, simbolo) VALUES (?, ?, ?)",
            [("H87", "Pieza", "pz"), ("E48", "Unidad de servicio", None)],
        )
        self.repo._persistent_conn.executemany(
            "INSERT OR IGNORE INTO sat_productos (clave, descripcion, palabras_similares) VALUES (?, ?, ?)",
            [
                ("01010101", "No existe en el catálogo", "Publico en general"),
                ("10101500", "Animales vivos de granja", None),
                ("10101501", "Perros", "Caninos"),
            ],
        )
        self.repo._persistent_conn.commit()

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

    def test_get_sat_regimenes_requires_productos_leer_permission(self):
        token = self._token_for(user_id=self.almacenista.id, company_id=1, email=self.almacenista.email)
        status, body = self._get("/api/sat/regimenes?page=1&per_page=1", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(body.get("meta", {}).get("total"), 2)
        self.assertEqual(len(body.get("data", [])), 1)

    def test_get_sat_unidades_invalid_page_returns_400(self):
        token = self._token_for(user_id=self.admin.id, company_id=1, email=self.admin.email)
        status, body = self._get("/api/sat/unidades?page=0&per_page=10", token=token)
        self.assertEqual(status, 400)
        self.assertEqual(body.get("error"), "validation_error")

    def test_get_sat_productos_supports_search_and_pagination(self):
        token = self._token_for(user_id=self.admin.id, company_id=1, email=self.admin.email)
        status, body = self._get("/api/sat/productos?search=perr&page=1&per_page=1", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(body.get("meta", {}).get("total"), 1)
        self.assertEqual(body.get("meta", {}).get("page"), 1)
        self.assertEqual(body.get("meta", {}).get("per_page"), 1)
        self.assertEqual(body.get("meta", {}).get("pages"), 1)
        self.assertEqual(body.get("data", [])[0].get("clave"), "10101501")

    def test_get_sat_productos_requires_auth(self):
        status, body = self._get("/api/sat/productos", token=None)
        self.assertEqual(status, 401)
        self.assertEqual(body.get("error"), "unauthorized")


if __name__ == "__main__":
    unittest.main()
