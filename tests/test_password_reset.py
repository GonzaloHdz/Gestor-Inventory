import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

from gestor_inventory.application.login_user import LoginRequest, login_user
from gestor_inventory.application.register_user import RegisterUserRequest, register_user
from gestor_inventory.application.request_password_reset import RequestPasswordResetRequest, request_password_reset
from gestor_inventory.application.reset_password import ResetPasswordRequest, reset_password
from gestor_inventory.domain.errors import PasswordResetTokenInvalidError, ValidationError
from gestor_inventory.infrastructure.sqlite_user_repository import SqliteUserRepository


class PasswordResetTests(unittest.TestCase):
    def setUp(self):
        self.repo = SqliteUserRepository(":memory:")
        self.jwt_secret = "test-secret"

    def test_password_reset_happy_path_updates_password(self):
        register_user(
            self.repo,
            RegisterUserRequest(company_id=1, email="user@example.com", password="OldPass1!", role_id=10),
        )
        res_req = request_password_reset(
            self.repo,
            RequestPasswordResetRequest(company_id=1, email="user@example.com"),
            now=1_000_000,
        )
        self.assertIsInstance(res_req.reset_token, str)
        self.assertTrue(res_req.reset_token)
        self.assertIn("company_id=1", res_req.reset_url)

        reset_password(
            self.repo,
            ResetPasswordRequest(company_id=1, token=res_req.reset_token, new_password="NewPass1!"),
            now=1_000_010,
        )

        login_user(
            self.repo,
            LoginRequest(company_id=1, email="user@example.com", password="NewPass1!"),
            jwt_secret=self.jwt_secret,
        )

    def test_password_reset_rejects_weak_password_with_clear_message(self):
        register_user(
            self.repo,
            RegisterUserRequest(company_id=1, email="user@example.com", password="OldPass1!", role_id=10),
        )
        res_req = request_password_reset(
            self.repo,
            RequestPasswordResetRequest(company_id=1, email="user@example.com"),
            now=1_000_000,
        )
        with self.assertRaises(ValidationError) as ctx:
            reset_password(
                self.repo,
                ResetPasswordRequest(company_id=1, token=res_req.reset_token, new_password="weak"),
                now=1_000_010,
            )
        msg = str(ctx.exception)
        self.assertIn("Contraseña débil", msg)
        self.assertIn("mínimo 8 caracteres", msg)

    def test_password_reset_token_is_one_time_use(self):
        register_user(
            self.repo,
            RegisterUserRequest(company_id=1, email="user@example.com", password="OldPass1!", role_id=10),
        )
        res_req = request_password_reset(
            self.repo,
            RequestPasswordResetRequest(company_id=1, email="user@example.com"),
            now=1_000_000,
        )
        reset_password(
            self.repo,
            ResetPasswordRequest(company_id=1, token=res_req.reset_token, new_password="NewPass1!"),
            now=1_000_010,
        )
        with self.assertRaises(PasswordResetTokenInvalidError):
            reset_password(
                self.repo,
                ResetPasswordRequest(company_id=1, token=res_req.reset_token, new_password="OtherPass1!"),
                now=1_000_020,
            )

    def test_password_reset_is_isolated_by_company(self):
        register_user(
            self.repo,
            RegisterUserRequest(company_id=1, email="a@b.com", password="OldPass1!", role_id=10),
        )
        register_user(
            self.repo,
            RegisterUserRequest(company_id=2, email="a@b.com", password="OldPass2!", role_id=10),
        )
        res_req = request_password_reset(
            self.repo,
            RequestPasswordResetRequest(company_id=1, email="a@b.com"),
            now=1_000_000,
        )
        with self.assertRaises(PasswordResetTokenInvalidError):
            reset_password(
                self.repo,
                ResetPasswordRequest(company_id=2, token=res_req.reset_token, new_password="NewPass1!"),
                now=1_000_010,
            )


if __name__ == "__main__":
    unittest.main()
