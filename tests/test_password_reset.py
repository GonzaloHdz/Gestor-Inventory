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
        reg = register_user(
            self.repo,
            RegisterUserRequest(email="user@example.com", password="OldPass1!", company_name="Reset One"),
        )
        res_req = request_password_reset(
            self.repo,
            RequestPasswordResetRequest(company_id=reg.company.id, email="user@example.com"),
            now=1_000_000,
        )
        self.assertIsInstance(res_req.reset_token, str)
        self.assertTrue(res_req.reset_token)
        self.assertIn(f"company_id={reg.company.id}", res_req.reset_url)

        reset_password(
            self.repo,
            ResetPasswordRequest(company_id=reg.company.id, token=res_req.reset_token, new_password="NewPass1!"),
            now=1_000_010,
        )
        self.repo._persistent_conn.execute("UPDATE users SET verified = 1 WHERE company_id = ? AND id = ?", (reg.company.id, reg.user.id))
        self.repo._persistent_conn.commit()

        login_user(
            self.repo,
            LoginRequest(company_id=reg.company.id, email="user@example.com", password="NewPass1!"),
            jwt_secret=self.jwt_secret,
        )

    def test_password_reset_rejects_weak_password_with_clear_message(self):
        reg = register_user(
            self.repo,
            RegisterUserRequest(email="user@example.com", password="OldPass1!", company_name="Reset Weak"),
        )
        res_req = request_password_reset(
            self.repo,
            RequestPasswordResetRequest(company_id=reg.company.id, email="user@example.com"),
            now=1_000_000,
        )
        with self.assertRaises(ValidationError) as ctx:
            reset_password(
                self.repo,
                ResetPasswordRequest(company_id=reg.company.id, token=res_req.reset_token, new_password="weak"),
                now=1_000_010,
            )
        msg = str(ctx.exception)
        self.assertIn("Contraseña débil", msg)
        self.assertIn("mínimo 8 caracteres", msg)

    def test_password_reset_token_is_one_time_use(self):
        reg = register_user(
            self.repo,
            RegisterUserRequest(email="user@example.com", password="OldPass1!", company_name="Reset Token"),
        )
        res_req = request_password_reset(
            self.repo,
            RequestPasswordResetRequest(company_id=reg.company.id, email="user@example.com"),
            now=1_000_000,
        )
        reset_password(
            self.repo,
            ResetPasswordRequest(company_id=reg.company.id, token=res_req.reset_token, new_password="NewPass1!"),
            now=1_000_010,
        )
        with self.assertRaises(PasswordResetTokenInvalidError):
            reset_password(
                self.repo,
                ResetPasswordRequest(company_id=reg.company.id, token=res_req.reset_token, new_password="OtherPass1!"),
                now=1_000_020,
            )

    def test_password_reset_is_isolated_by_company(self):
        reg_a = register_user(
            self.repo,
            RegisterUserRequest(email="a@b.com", password="OldPass1!", company_name="Reset A"),
        )
        reg_b = register_user(
            self.repo,
            RegisterUserRequest(email="a@b.com", password="OldPass2!", company_name="Reset B"),
        )
        res_req = request_password_reset(
            self.repo,
            RequestPasswordResetRequest(company_id=reg_a.company.id, email="a@b.com"),
            now=1_000_000,
        )
        with self.assertRaises(PasswordResetTokenInvalidError):
            reset_password(
                self.repo,
                ResetPasswordRequest(company_id=reg_b.company.id, token=res_req.reset_token, new_password="NewPass1!"),
                now=1_000_010,
            )


if __name__ == "__main__":
    unittest.main()
