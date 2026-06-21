import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

from gestor_inventory.application.login_user import LoginRequest, login_user
from gestor_inventory.application.logout_user import LogoutRequest, logout_user
from gestor_inventory.application.refresh_access_token import RefreshAccessTokenRequest, refresh_access_token
from gestor_inventory.application.register_user import RegisterUserRequest, register_user
from gestor_inventory.domain.errors import RefreshTokenInvalidError
from gestor_inventory.infrastructure.sqlite_user_repository import SqliteUserRepository


class LogoutUserTests(unittest.TestCase):
    def setUp(self):
        self.repo = SqliteUserRepository(":memory:")
        self.reg = register_user(
            self.repo,
            RegisterUserRequest(email="logout@example.com", password="Secret1!", company_name="Logout Co"),
        )
        self.repo._persistent_conn.execute(
            "UPDATE users SET verified = 1 WHERE company_id = ? AND id = ?",
            (self.reg.company.id, self.reg.user.id),
        )
        self.repo._persistent_conn.commit()

    def test_logout_invalidates_refresh_token(self):
        login_res = login_user(
            self.repo,
            LoginRequest(company_id=self.reg.company.id, email="logout@example.com", password="Secret1!"),
            jwt_secret="test-secret",
            now=1_700_000_000,
        )

        logout_user(
            self.repo,
            LogoutRequest(company_id=self.reg.company.id, refresh_token=login_res.refresh_token),
            now=1_700_000_100,
        )

        with self.assertRaises(RefreshTokenInvalidError):
            refresh_access_token(
                self.repo,
                RefreshAccessTokenRequest(company_id=self.reg.company.id, refresh_token=login_res.refresh_token),
                jwt_secret="test-secret",
                now=1_700_000_200,
            )

    def test_logout_rejects_reusing_same_refresh_token(self):
        login_res = login_user(
            self.repo,
            LoginRequest(company_id=self.reg.company.id, email="logout@example.com", password="Secret1!"),
            jwt_secret="test-secret",
            now=1_700_000_000,
        )

        logout_user(
            self.repo,
            LogoutRequest(company_id=self.reg.company.id, refresh_token=login_res.refresh_token),
            now=1_700_000_100,
        )

        with self.assertRaises(RefreshTokenInvalidError):
            logout_user(
                self.repo,
                LogoutRequest(company_id=self.reg.company.id, refresh_token=login_res.refresh_token),
                now=1_700_000_200,
            )


if __name__ == "__main__":
    unittest.main()
