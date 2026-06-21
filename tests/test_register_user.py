import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

from gestor_inventory.application.register_user import RegisterUserRequest, register_user
from gestor_inventory.domain.errors import CompanyNameAlreadyExistsError, ValidationError
from gestor_inventory.infrastructure.sqlite_user_repository import SqliteUserRepository
from gestor_inventory.security.password_hash import verify_password


class RegisterUserTests(unittest.TestCase):
    def setUp(self):
        self.repo = SqliteUserRepository(":memory:")

    def test_register_user_success_creates_company_and_admin_owner(self):
        res = register_user(
            self.repo,
            RegisterUserRequest(
                email="User@Example.com",
                password="Secret1!",
                company_name="Mi Empresa",
                currency="MXN",
                timezone="America/Mexico_City",
            ),
        )
        self.assertGreater(res.company.id, 0)
        self.assertEqual(res.company.name, "Mi Empresa")
        self.assertEqual(res.company.currency, "MXN")
        self.assertEqual(res.company.timezone, "America/Mexico_City")
        self.assertEqual(res.user.company_id, res.company.id)
        self.assertEqual(res.user.email, "user@example.com")
        self.assertTrue(res.user.is_active)
        self.assertFalse(res.user.verified)
        self.assertEqual(res.role_id, 12)
        self.assertIn(f"company_id={res.company.id}", res.verification_url)
        self.assertTrue(verify_password("Secret1!", res.user.password_hash))

    def test_register_user_rejects_weak_password_with_clear_message(self):
        with self.assertRaises(ValidationError) as ctx:
            register_user(
                self.repo,
                RegisterUserRequest(email="user@example.com", password="weak", company_name="Empresa Debil"),
            )
        msg = str(ctx.exception)
        self.assertIn("Contraseña débil", msg)
        self.assertIn("mínimo 8 caracteres", msg)
        self.assertIn("letra mayúscula", msg)
        self.assertIn("número", msg)
        self.assertIn("carácter especial", msg)

    def test_register_user_rejects_duplicate_company_name(self):
        register_user(
            self.repo,
            RegisterUserRequest(email="a@b.com", password="Secret1!", company_name="Empresa Uno"),
        )
        with self.assertRaises(CompanyNameAlreadyExistsError):
            register_user(
                self.repo,
                RegisterUserRequest(email="otro@b.com", password="Secret2!", company_name="Empresa Uno"),
            )

    def test_register_user_allows_same_email_in_different_new_companies(self):
        res_a = register_user(
            self.repo,
            RegisterUserRequest(email="a@b.com", password="Secret1!", company_name="Empresa A"),
        )
        res_b = register_user(
            self.repo,
            RegisterUserRequest(email="a@b.com", password="Secret1!", company_name="Empresa B"),
        )
        self.assertNotEqual(res_a.company.id, res_b.company.id)
        self.assertNotEqual(res_a.user.company_id, res_b.user.company_id)

    def test_register_user_autogenerates_company_name_when_missing(self):
        res = register_user(
            self.repo,
            RegisterUserRequest(email="founder@example.com", password="Secret1!"),
        )
        self.assertEqual(res.company.name, "Empresa de founder")


if __name__ == "__main__":
    unittest.main()
