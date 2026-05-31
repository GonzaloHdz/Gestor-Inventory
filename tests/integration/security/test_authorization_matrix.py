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


class AuthorizationIntegrationTests(unittest.TestCase):
    def setUp(self):
        self._prev_secret = HttpApiHandler.jwt_secret
        self._prev_repo = HttpApiHandler.repo
        self._prev_exp = getattr(HttpApiHandler, "jwt_expiration_minutes", 60)

        self.repo = SqliteUserRepository(":memory:")
        HttpApiHandler.repo = self.repo
        HttpApiHandler.jwt_secret = "test-secret"
        HttpApiHandler.jwt_expiration_minutes = 60

        password_hash_v = hash_password("Strong1!")

        self.users = {
            (1, 10): self.repo.create_user_with_role(
                company_id=1, email="almacenista1@example.com", password_hash=password_hash_v, role_id=10
            )[0],
            (1, 11): self.repo.create_user_with_role(
                company_id=1, email="supervisor1@example.com", password_hash=password_hash_v, role_id=11
            )[0],
            (1, 12): self.repo.create_user_with_role(
                company_id=1, email="admin1@example.com", password_hash=password_hash_v, role_id=12
            )[0],
            (1, 13): self.repo.create_user_with_role(
                company_id=1, email="superadmin1@example.com", password_hash=password_hash_v, role_id=13
            )[0],
            (2, 12): self.repo.create_user_with_role(
                company_id=2, email="admin2@example.com", password_hash=password_hash_v, role_id=12
            )[0],
            (2, 10): self.repo.create_user_with_role(
                company_id=2, email="almacenista2@example.com", password_hash=password_hash_v, role_id=10
            )[0],
        }

        self.target_company1, _ = self.repo.create_user_with_role(
            company_id=1, email="target1@example.com", password_hash=password_hash_v, role_id=10
        )
        self.target_company2, _ = self.repo.create_user_with_role(
            company_id=2, email="target2@example.com", password_hash=password_hash_v, role_id=10
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

    def test_matrix_access_by_role(self):
        matrix = [
            ("GET", "/api/admin/roles", None),
            ("GET", "/api/admin/permissions", None),
            ("POST", "/api/admin/user-roles/assign", {"company_id": 1, "user_id": None, "role_id": 11}),
            ("POST", "/api/admin/user-roles/revoke", {"company_id": 1, "user_id": None, "role_id": 11}),
        ]

        expected_allowed_role_ids = {
            "/api/admin/roles": {12, 13},
            "/api/admin/permissions": {12, 13},
            "/api/admin/user-roles/assign": {12, 13},
            "/api/admin/user-roles/revoke": {12, 13},
        }

        self.repo.assign_role_to_user(company_id=1, user_id=self.target_company1.id, role_id=11)

        for role_id in (10, 11, 12, 13):
            actor = self.users[(1, role_id)]
            token = self._token_for(user_id=actor.id, company_id=1, email=actor.email)
            for method, path, body in matrix:
                with self.subTest(role_id=role_id, method=method, path=path):
                    if method == "GET":
                        status, _ = self._get(path, token=token)
                    else:
                        payload = dict(body or {})
                        payload["user_id"] = self.target_company1.id
                        status, _ = self._post(path, payload, token=token)
                    if role_id in expected_allowed_role_ids[path]:
                        self.assertEqual(status, 200)
                    else:
                        self.assertEqual(status, 403)

    def test_multi_tenant_isolation_never_returns_200(self):
        admin = self.users[(1, 12)]
        token = self._token_for(user_id=admin.id, company_id=1, email=admin.email)

        status_a, _ = self._post(
            "/api/admin/user-roles/assign",
            {"company_id": 2, "user_id": self.target_company2.id, "role_id": 11},
            token=token,
        )
        self.assertIn(status_a, (403, 404))

        status_b, _ = self._post(
            "/api/admin/user-roles/assign",
            {"company_id": 1, "user_id": self.target_company2.id, "role_id": 11},
            token=token,
        )
        self.assertIn(status_b, (403, 404))

    def test_deny_by_default_admin_prefix(self):
        status, _ = self._get("/api/admin/does-not-exist", token=None)
        self.assertEqual(status, 403)

