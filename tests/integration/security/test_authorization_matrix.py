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

    def _token_for(self, *, user_id: int, company_id: int, email: str, branch_id: int | None = None) -> str:
        claims = {"sub": str(user_id), "company_id": int(company_id), "email": str(email)}
        if branch_id is not None:
            claims["branch_id"] = int(branch_id)
        return create_jwt_hs256(claims, secret="test-secret", expires_in_seconds=60)

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

    def _patch(self, path: str, body: dict, token: str | None) -> tuple[int, dict]:
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

    def _data_audit_logs(self) -> list[dict]:
        conn = self.repo._persistent_conn
        rows = conn.execute(
            "SELECT company_id, user_id, action, resource, details FROM audit_logs ORDER BY id"
        ).fetchall()
        return [
            {"company_id": int(c), "user_id": int(u), "action": str(a), "resource": str(r), "details": d}
            for (c, u, a, r, d) in rows
        ]

    def _companies(self) -> list[dict]:
        conn = self.repo._persistent_conn
        rows = conn.execute("SELECT id, name, currency, timezone, status FROM companies ORDER BY id").fetchall()
        return [
            {"id": int(i), "name": str(n), "currency": str(c), "timezone": str(t), "status": str(s)} for (i, n, c, t, s) in rows
        ]

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

    def test_operational_resource_isolation_category_by_company_id(self):
        category_company2 = self.repo.create_category(company_id=2, name="Bebidas", is_active=True)

        admin_company1 = self.users[(1, 12)]
        token = self._token_for(user_id=admin_company1.id, company_id=1, email=admin_company1.email)
        status, _ = self._get(f"/api/admin/categories/{category_company2.id}", token=token)
        self.assertIn(status, (403, 404))

    def test_operational_write_requires_permission(self):
        almacenista_company1 = self.users[(1, 10)]
        token = self._token_for(user_id=almacenista_company1.id, company_id=1, email=almacenista_company1.email)
        status, _ = self._post("/api/admin/categories", {"name": "Lácteos"}, token=token)
        self.assertEqual(status, 403)

        admin_company1 = self.users[(1, 12)]
        token_admin = self._token_for(user_id=admin_company1.id, company_id=1, email=admin_company1.email)
        status_ok, body_ok = self._post("/api/admin/categories", {"name": "Lácteos"}, token=token_admin)
        self.assertEqual(status_ok, 201)
        self.assertEqual(body_ok.get("category", {}).get("company_id"), 1)
        logs = self._data_audit_logs()
        self.assertTrue(any(l["company_id"] == 1 and l["user_id"] == admin_company1.id and l["action"] == "CREATE" and l["resource"] == "categorias" for l in logs))

    def test_create_branch_requires_permission(self):
        almacenista_company1 = self.users[(1, 10)]
        token = self._token_for(user_id=almacenista_company1.id, company_id=1, email=almacenista_company1.email)
        status, _ = self._post("/api/admin/branches", {"name": "Sucursal A"}, token=token)
        self.assertEqual(status, 403)

        admin_company1 = self.users[(1, 12)]
        token_admin = self._token_for(user_id=admin_company1.id, company_id=1, email=admin_company1.email)
        status_ok, body_ok = self._post("/api/admin/branches", {"name": "Sucursal A"}, token=token_admin)
        self.assertEqual(status_ok, 201)
        self.assertEqual(body_ok.get("branch", {}).get("company_id"), 1)

    def test_cross_tenant_category_reference_is_rejected_on_product_create(self):
        category_company2 = self.repo.create_category(company_id=2, name="Cat 2", is_active=True)
        admin_company1 = self.users[(1, 12)]
        token = self._token_for(user_id=admin_company1.id, company_id=1, email=admin_company1.email)
        status, body = self._post(
            "/api/admin/products",
            {"sku": "SKU-X", "name": "Producto X", "category_id": category_company2.id},
            token=token,
        )
        self.assertEqual(status, 400)
        self.assertEqual(body.get("error"), "validation_error")

    def test_create_branch_rejects_inactive_company(self):
        conn = self.repo._persistent_conn
        conn.execute("UPDATE companies SET status = 'inactive' WHERE id = 1")
        conn.commit()

        admin_company1 = self.users[(1, 12)]
        token_admin = self._token_for(user_id=admin_company1.id, company_id=1, email=admin_company1.email)
        status, body = self._post("/api/admin/branches", {"name": "Sucursal Inactiva"}, token=token_admin)
        self.assertIn(status, (400, 404))
        if status == 400:
            self.assertEqual(body.get("error"), "validation_error")

        row = conn.execute(
            "SELECT 1 FROM branches WHERE company_id = 1 AND name = ? LIMIT 1",
            ("Sucursal Inactiva",),
        ).fetchone()
        self.assertIsNone(row)

    def test_set_company_default_branch_requires_superadmin_permission(self):
        branch_company1 = self.repo.create_branch(
            company_id=1,
            name="Sucursal Default",
            address=None,
            city=None,
            country=None,
            status="active",
            is_active=True,
        )

        admin_company1 = self.users[(1, 12)]
        token_admin = self._token_for(user_id=admin_company1.id, company_id=1, email=admin_company1.email)
        status_forbidden, _ = self._patch(
            "/api/admin/companies/default-branch",
            {"default_branch_id": branch_company1.id},
            token=token_admin,
        )
        self.assertEqual(status_forbidden, 403)

        superadmin_company1 = self.users[(1, 13)]
        token_super = self._token_for(user_id=superadmin_company1.id, company_id=1, email=superadmin_company1.email)
        status_ok, body_ok = self._patch(
            "/api/admin/companies/default-branch",
            {"default_branch_id": branch_company1.id},
            token=token_super,
        )
        self.assertEqual(status_ok, 200)
        self.assertEqual(body_ok.get("default_branch_id"), branch_company1.id)

        conn = self.repo._persistent_conn
        row = conn.execute("SELECT default_branch_id FROM companies WHERE id = 1").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(int(row[0]), branch_company1.id)

        logs = self._data_audit_logs()
        self.assertTrue(
            any(
                l["company_id"] == 1
                and l["user_id"] == superadmin_company1.id
                and l["action"] == "UPDATE"
                and l["resource"] == "empresas"
                for l in logs
            )
        )

    def test_set_company_default_branch_rejects_cross_tenant(self):
        branch_company2 = self.repo.create_branch(
            company_id=2,
            name="Sucursal B Default",
            address=None,
            city=None,
            country=None,
            status="active",
            is_active=True,
        )
        superadmin_company1 = self.users[(1, 13)]
        token_super = self._token_for(user_id=superadmin_company1.id, company_id=1, email=superadmin_company1.email)
        status, body = self._patch(
            "/api/admin/companies/default-branch",
            {"default_branch_id": branch_company2.id},
            token=token_super,
        )
        self.assertIn(status, (400, 403))
        if status == 400:
            self.assertEqual(body.get("error"), "validation_error")

    def test_inventory_endpoint_requires_token_and_filters_by_company_and_branch(self):
        status_unauth, _ = self._get("/api/inventory?branch_id=1", token=None)
        self.assertEqual(status_unauth, 401)

        admin_company1 = self.users[(1, 12)]
        token = self._token_for(user_id=admin_company1.id, company_id=1, email=admin_company1.email)

        branch1 = self.repo.create_branch(company_id=1, name="Casa Central", address=None, is_active=True)
        branch2_other = self.repo.create_branch(company_id=2, name="Sucursal 2", address=None, is_active=True)
        category1 = self.repo.create_category(company_id=1, name="Cat Inv", is_active=True)
        product = self.repo.create_product(
            company_id=1, category_id=category1.id, sku="SKU-1", name="Prod 1", description=None, is_active=True
        )
        self.repo.upsert_inventory_item(
            company_id=1, branch_id=branch1.id, product_id=product.id, quantity=5, min_quantity=0, updated_at=123
        )

        status_ok, body_ok = self._get(f"/api/inventory?branch_id={branch1.id}", token=token)
        self.assertEqual(status_ok, 200)
        items = body_ok.get("items")
        self.assertIsInstance(items, list)
        self.assertTrue(all(i.get("company_id") == 1 and i.get("branch_id") == branch1.id for i in items))
        logs = self._data_audit_logs()
        self.assertTrue(any(l["company_id"] == 1 and l["user_id"] == admin_company1.id and l["action"] == "READ" and l["resource"] == "inventario" for l in logs))

        status_cross, _ = self._get(f"/api/inventory?branch_id={branch2_other.id}", token=token)
        self.assertEqual(status_cross, 404)

    def test_branch_level_isolation_denies_cross_branch_for_operational_user(self):
        branch1 = self.repo.create_branch(company_id=1, name="Sucursal 1", address=None, is_active=True)
        branch2 = self.repo.create_branch(company_id=1, name="Sucursal 2", address=None, is_active=True)
        category1 = self.repo.create_category(company_id=1, name="Cat BR", is_active=True)
        product = self.repo.create_product(company_id=1, category_id=category1.id, sku="SKU-BR", name="Prod BR", description=None, is_active=True)
        self.repo.upsert_inventory_item(
            company_id=1, branch_id=branch1.id, product_id=product.id, quantity=1, min_quantity=0, updated_at=123
        )
        self.repo.upsert_inventory_item(
            company_id=1, branch_id=branch2.id, product_id=product.id, quantity=2, min_quantity=0, updated_at=124
        )

        almacenista_company1 = self.users[(1, 10)]
        token = self._token_for(
            user_id=almacenista_company1.id,
            company_id=1,
            email=almacenista_company1.email,
            branch_id=branch1.id,
        )

        status_ok, _ = self._get(f"/api/inventory?branch_id={branch1.id}", token=token)
        self.assertEqual(status_ok, 200)

        status_forbidden, body_forbidden = self._get(f"/api/inventory?branch_id={branch2.id}", token=token)
        self.assertEqual(status_forbidden, 403)
        self.assertEqual(body_forbidden.get("error"), "forbidden")

    def test_branch_level_isolation_allows_admin_across_branches(self):
        branch1 = self.repo.create_branch(company_id=1, name="Sucursal 1 Admin", address=None, is_active=True)
        branch2 = self.repo.create_branch(company_id=1, name="Sucursal 2 Admin", address=None, is_active=True)
        category1 = self.repo.create_category(company_id=1, name="Cat ADM", is_active=True)
        product = self.repo.create_product(company_id=1, category_id=category1.id, sku="SKU-ADM", name="Prod ADM", description=None, is_active=True)
        self.repo.upsert_inventory_item(
            company_id=1, branch_id=branch1.id, product_id=product.id, quantity=3, min_quantity=0, updated_at=125
        )
        self.repo.upsert_inventory_item(
            company_id=1, branch_id=branch2.id, product_id=product.id, quantity=4, min_quantity=0, updated_at=126
        )

        admin_company1 = self.users[(1, 12)]
        token = self._token_for(user_id=admin_company1.id, company_id=1, email=admin_company1.email)

        status1, body1 = self._get(f"/api/inventory?branch_id={branch1.id}", token=token)
        self.assertEqual(status1, 200)
        self.assertTrue(all(i.get("company_id") == 1 and i.get("branch_id") == branch1.id for i in body1.get("items", [])))

        status2, body2 = self._get(f"/api/inventory?branch_id={branch2.id}", token=token)
        self.assertEqual(status2, 200)
        self.assertTrue(all(i.get("company_id") == 1 and i.get("branch_id") == branch2.id for i in body2.get("items", [])))

    def test_role_assignment_is_audited(self):
        admin_company1 = self.users[(1, 12)]
        token = self._token_for(user_id=admin_company1.id, company_id=1, email=admin_company1.email)
        status, _ = self._post(
            "/api/admin/user-roles/assign",
            {"company_id": 1, "user_id": self.target_company1.id, "role_id": 11},
            token=token,
        )
        self.assertEqual(status, 200)
        logs = self._data_audit_logs()
        self.assertTrue(any(l["company_id"] == 1 and l["user_id"] == admin_company1.id and l["action"] == "CREATE" and l["resource"] == "roles" for l in logs))

    def test_create_company_requires_superadmin_permission(self):
        admin_company1 = self.users[(1, 12)]
        token = self._token_for(user_id=admin_company1.id, company_id=1, email=admin_company1.email)
        status, _ = self._post(
            "/api/admin/companies",
            {"name": "Empresa X", "currency": "USD", "timezone": "UTC"},
            token=token,
        )
        self.assertEqual(status, 403)

    def test_create_company_success_and_audit(self):
        superadmin_company1 = self.users[(1, 13)]
        token = self._token_for(user_id=superadmin_company1.id, company_id=1, email=superadmin_company1.email)
        status, body = self._post(
            "/api/admin/companies",
            {"name": "Empresa Nueva", "currency": "USD", "timezone": "UTC"},
            token=token,
        )
        self.assertEqual(status, 201)
        self.assertIsInstance(body.get("company_id"), int)
        companies = self._companies()
        self.assertTrue(any(c["name"] == "Empresa Nueva" for c in companies))
        logs = self._data_audit_logs()
        self.assertTrue(any(l["company_id"] == 1 and l["user_id"] == superadmin_company1.id and l["action"] == "CREATE" and l["resource"] == "empresas" for l in logs))

    def test_create_company_duplicate_name_conflict(self):
        superadmin_company1 = self.users[(1, 13)]
        token = self._token_for(user_id=superadmin_company1.id, company_id=1, email=superadmin_company1.email)
        status1, _ = self._post(
            "/api/admin/companies",
            {"name": "Empresa Duplicada", "currency": "USD", "timezone": "UTC"},
            token=token,
        )
        self.assertEqual(status1, 201)
        status2, body2 = self._post(
            "/api/admin/companies",
            {"name": "Empresa Duplicada", "currency": "USD", "timezone": "UTC"},
            token=token,
        )
        self.assertEqual(status2, 409)
        self.assertEqual(body2.get("error"), "company_name_exists")

    def test_list_companies_requires_permission(self):
        admin_company1 = self.users[(1, 12)]
        token = self._token_for(user_id=admin_company1.id, company_id=1, email=admin_company1.email)
        status, _ = self._get("/api/admin/companies?page=1&per_page=10", token=token)
        self.assertEqual(status, 403)

    def test_list_companies_pagination_and_audit(self):
        superadmin_company1 = self.users[(1, 13)]
        token = self._token_for(user_id=superadmin_company1.id, company_id=1, email=superadmin_company1.email)

        initial_total = len(self._companies())
        for i in range(12):
            status_c, _ = self._post(
                "/api/admin/companies",
                {"name": f"Empresa Test {i}", "currency": "USD", "timezone": "UTC"},
                token=token,
            )
            self.assertEqual(status_c, 201)

        status, body = self._get("/api/admin/companies?page=1&per_page=10", token=token)
        self.assertEqual(status, 200)
        self.assertIsInstance(body.get("data"), list)
        self.assertEqual(len(body["data"]), 10)
        self.assertEqual(body.get("pagination", {}).get("total"), initial_total + 12)
        self.assertEqual(body.get("pagination", {}).get("page"), 1)
        self.assertEqual(body.get("pagination", {}).get("per_page"), 10)
        self.assertEqual(body.get("pagination", {}).get("pages"), 2)
        self.assertTrue(all(row.get("status") == "active" for row in body["data"]))
        self.assertTrue(all(isinstance(row.get("created_at"), str) for row in body["data"]))

        logs = self._data_audit_logs()
        self.assertTrue(
            any(
                l["company_id"] == 1
                and l["user_id"] == superadmin_company1.id
                and l["action"] == "READ"
                and l["resource"] == "empresas"
                for l in logs
            )
        )
