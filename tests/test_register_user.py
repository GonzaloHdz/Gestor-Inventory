import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

from gestor_inventory.application.register_user import RegisterUserRequest, register_user
from gestor_inventory.domain.errors import EmailAlreadyExistsError, ValidationError
from gestor_inventory.infrastructure.sqlite_user_repository import SqliteUserRepository
from gestor_inventory.security.password_hash import verify_password


class RegisterUserTests(unittest.TestCase):
    def setUp(self):
        self.repo = SqliteUserRepository(":memory:")

    def test_register_user_success(self):
        res = register_user(
            self.repo,
            RegisterUserRequest(company_id=1, email="User@Example.com", password="Secret1!", role_id=10),
        )
        self.assertEqual(res.user.company_id, 1)
        self.assertEqual(res.user.email, "user@example.com")
        self.assertTrue(res.user.is_active)
        self.assertFalse(res.user.verified)
        self.assertEqual(res.role_id, 10)
        self.assertIn("company_id=1", res.verification_url)
        self.assertTrue(verify_password("Secret1!", res.user.password_hash))

    def test_register_user_rejects_weak_password_with_clear_message(self):
        with self.assertRaises(ValidationError) as ctx:
            register_user(
                self.repo,
                RegisterUserRequest(company_id=1, email="user@example.com", password="weak", role_id=10),
            )
        msg = str(ctx.exception)
        self.assertIn("Contraseña débil", msg)
        self.assertIn("mínimo 8 caracteres", msg)
        self.assertIn("letra mayúscula", msg)
        self.assertIn("número", msg)
        self.assertIn("carácter especial", msg)

    def test_register_user_rejects_duplicate_email_same_company(self):
        register_user(
            self.repo,
            RegisterUserRequest(company_id=1, email="a@b.com", password="Secret1!", role_id=10),
        )
        with self.assertRaises(EmailAlreadyExistsError):
            register_user(
                self.repo,
                RegisterUserRequest(company_id=1, email="a@b.com", password="Secret2!", role_id=10),
            )

    def test_register_user_allows_same_email_different_company(self):
        register_user(
            self.repo,
            RegisterUserRequest(company_id=1, email="a@b.com", password="Secret1!", role_id=10),
        )
        res = register_user(
            self.repo,
            RegisterUserRequest(company_id=2, email="a@b.com", password="Secret1!", role_id=10),
        )
        self.assertEqual(res.user.company_id, 2)


if __name__ == "__main__":
    unittest.main()
