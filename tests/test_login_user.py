import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

from gestor_inventory.application.login_user import LoginRequest, login_user
from gestor_inventory.application.register_user import RegisterUserRequest, register_user
from gestor_inventory.domain.errors import AccountNotVerifiedError, InvalidCredentialsError
from gestor_inventory.infrastructure.sqlite_user_repository import SqliteUserRepository
from gestor_inventory.security.jwt import verify_jwt_hs256


class LoginUserTests(unittest.TestCase):
    def setUp(self):
        self.repo = SqliteUserRepository(":memory:")
        self.jwt_secret = "test-secret"

    def test_login_success_returns_valid_jwt(self):
        reg = register_user(
            self.repo,
            RegisterUserRequest(email="User@Example.com", password="Secret1!", company_name="Login OK"),
        )
        self.repo._persistent_conn.execute("UPDATE users SET verified = 1 WHERE company_id = ? AND id = ?", (reg.company.id, reg.user.id))
        self.repo._persistent_conn.commit()
        res = login_user(
            self.repo,
            LoginRequest(company_id=reg.company.id, email="user@example.com", password="Secret1!"),
            jwt_secret=self.jwt_secret,
            access_token_ttl_seconds=3600,
        )
        payload = verify_jwt_hs256(res.access_token, secret=self.jwt_secret)
        self.assertEqual(payload["company_id"], reg.company.id)
        self.assertEqual(payload["email"], "user@example.com")
        self.assertEqual(payload["sub"], str(reg.user.id))

    def test_login_invalid_password_is_generic_failure(self):
        reg = register_user(
            self.repo,
            RegisterUserRequest(email="a@b.com", password="Secret1!", company_name="Invalid Password Co"),
        )
        self.repo._persistent_conn.execute("UPDATE users SET verified = 1 WHERE company_id = ? AND id = ?", (reg.company.id, reg.user.id))
        self.repo._persistent_conn.commit()
        with self.assertRaises(InvalidCredentialsError):
            login_user(
                self.repo,
                LoginRequest(company_id=reg.company.id, email="a@b.com", password="wrong"),
                jwt_secret=self.jwt_secret,
            )

    def test_login_invalid_email_is_generic_failure(self):
        reg = register_user(
            self.repo,
            RegisterUserRequest(email="a@b.com", password="Secret1!", company_name="Invalid Email Co"),
        )
        self.repo._persistent_conn.execute("UPDATE users SET verified = 1 WHERE company_id = ? AND id = ?", (reg.company.id, reg.user.id))
        self.repo._persistent_conn.commit()
        with self.assertRaises(InvalidCredentialsError):
            login_user(
                self.repo,
                LoginRequest(company_id=reg.company.id, email="x@y.com", password="Secret1!"),
                jwt_secret=self.jwt_secret,
            )

    def test_login_is_isolated_by_company(self):
        register_user(
            self.repo,
            RegisterUserRequest(email="a@b.com", password="Secret1!", company_name="Isolation Co"),
        )
        with self.assertRaises(InvalidCredentialsError):
            login_user(
                self.repo,
                LoginRequest(company_id=2, email="a@b.com", password="Secret1!"),
                jwt_secret=self.jwt_secret,
            )

    def test_login_rejects_unverified_user_with_specific_error(self):
        reg = register_user(
            self.repo,
            RegisterUserRequest(email="pending@example.com", password="Secret1!", company_name="Pending Co"),
        )
        with self.assertRaises(AccountNotVerifiedError):
            login_user(
                self.repo,
                LoginRequest(company_id=reg.company.id, email="pending@example.com", password="Secret1!"),
                jwt_secret=self.jwt_secret,
            )


if __name__ == "__main__":
    unittest.main()
