import os
import sys
import unittest
from urllib.parse import parse_qs, urlparse

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

from gestor_inventory.application.create_internal_user import CreateInternalUserRequest, create_internal_user
from gestor_inventory.domain.errors import EmailAlreadyExistsError, ForbiddenError, NotFoundError
from gestor_inventory.infrastructure.sqlite_user_repository import SqliteUserRepository


class CreateInternalUserTests(unittest.TestCase):
    def setUp(self):
        self.repo = SqliteUserRepository(":memory:")
        self.admin_user, _ = self.repo.create_user_with_role(
            company_id=1,
            email="admin@example.com",
            password_hash="hash-admin",
            role_id=12,
        )
        self.superadmin_user, _ = self.repo.create_user_with_role(
            company_id=1,
            email="superadmin@example.com",
            password_hash="hash-superadmin",
            role_id=13,
        )

    def test_admin_creates_internal_user_in_same_company(self):
        res = create_internal_user(
            self.repo,
            CreateInternalUserRequest(
                company_id=1,
                actor_user_id=self.admin_user.id,
                email="empleado@example.com",
                password="Secret1!",
                role_id=10,
            ),
            base_url="http://localhost:8000",
            now=1_000_000,
        )
        self.assertEqual(res.user.company_id, 1)
        self.assertEqual(res.user.email, "empleado@example.com")
        self.assertFalse(res.user.verified)
        self.assertEqual(res.role_id, 10)
        parsed = urlparse(res.verification_url)
        params = parse_qs(parsed.query)
        self.assertEqual(parsed.path, "/api/auth/verify")
        self.assertTrue(params["token"][0].startswith("1."))

    def test_admin_cannot_create_superadmin(self):
        with self.assertRaises(ForbiddenError):
            create_internal_user(
                self.repo,
                CreateInternalUserRequest(
                    company_id=1,
                    actor_user_id=self.admin_user.id,
                    email="nope@example.com",
                    password="Secret1!",
                    role_id=13,
                ),
            )

    def test_superadmin_can_create_superadmin(self):
        res = create_internal_user(
            self.repo,
            CreateInternalUserRequest(
                company_id=1,
                actor_user_id=self.superadmin_user.id,
                email="nuevo-super@example.com",
                password="Secret1!",
                role_id=13,
            ),
        )
        self.assertEqual(res.role_id, 13)
        role_names = set(self.repo.list_user_role_names(company_id=1, user_id=res.user.id))
        self.assertIn("Superadministrador", role_names)

    def test_rejects_duplicate_email_in_same_company(self):
        create_internal_user(
            self.repo,
            CreateInternalUserRequest(
                company_id=1,
                actor_user_id=self.admin_user.id,
                email="empleado@example.com",
                password="Secret1!",
                role_id=10,
            ),
        )
        with self.assertRaises(EmailAlreadyExistsError):
            create_internal_user(
                self.repo,
                CreateInternalUserRequest(
                    company_id=1,
                    actor_user_id=self.admin_user.id,
                    email="empleado@example.com",
                    password="Secret1!",
                    role_id=11,
                ),
            )

    def test_rejects_unknown_role(self):
        with self.assertRaises(NotFoundError):
            create_internal_user(
                self.repo,
                CreateInternalUserRequest(
                    company_id=1,
                    actor_user_id=self.admin_user.id,
                    email="empleado@example.com",
                    password="Secret1!",
                    role_id=999,
                ),
            )


if __name__ == "__main__":
    unittest.main()
