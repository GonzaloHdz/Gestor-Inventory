import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

from gestor_inventory.application.login_user import LoginRequest, login_user
from gestor_inventory.application.refresh_access_token import (
    RefreshAccessTokenRequest,
    refresh_access_token,
)
from gestor_inventory.application.register_user import RegisterUserRequest, register_user
from gestor_inventory.domain.errors import RefreshTokenInvalidError
from gestor_inventory.infrastructure.sqlite_user_repository import SqliteUserRepository
from gestor_inventory.security.jwt import verify_jwt_hs256


class RefreshAccessTokenTests(unittest.TestCase):
    def setUp(self):
        self.repo = SqliteUserRepository(":memory:")
        self.jwt_secret = "test-secret"
        self.reg = register_user(
            self.repo,
            RegisterUserRequest(email="refresh@example.com", password="Secret1!", company_name="Refresh Co"),
        )
        self.repo._persistent_conn.execute(
            "UPDATE users SET verified = 1 WHERE company_id = ? AND id = ?",
            (self.reg.company.id, self.reg.user.id),
        )
        self.repo._persistent_conn.commit()

    def test_refresh_success_rotates_token_and_returns_new_access_token(self):
        login_res = login_user(
            self.repo,
            LoginRequest(company_id=self.reg.company.id, email="refresh@example.com", password="Secret1!"),
            jwt_secret=self.jwt_secret,
            access_token_ttl_seconds=3600,
            refresh_token_ttl_seconds=86400,
            now=1_700_000_000,
        )

        refresh_res = refresh_access_token(
            self.repo,
            RefreshAccessTokenRequest(
                company_id=self.reg.company.id,
                refresh_token=login_res.refresh_token,
            ),
            jwt_secret=self.jwt_secret,
            access_token_ttl_seconds=3600,
            refresh_token_ttl_seconds=86400,
            now=1_700_000_100,
        )

        payload = verify_jwt_hs256(refresh_res.access_token, secret=self.jwt_secret)
        self.assertEqual(payload["company_id"], self.reg.company.id)
        self.assertEqual(payload["sub"], str(self.reg.user.id))
        self.assertNotEqual(refresh_res.refresh_token, login_res.refresh_token)

    def test_refresh_rejects_reuse_of_already_consumed_token(self):
        login_res = login_user(
            self.repo,
            LoginRequest(company_id=self.reg.company.id, email="refresh@example.com", password="Secret1!"),
            jwt_secret=self.jwt_secret,
            now=1_700_000_000,
        )

        refresh_access_token(
            self.repo,
            RefreshAccessTokenRequest(company_id=self.reg.company.id, refresh_token=login_res.refresh_token),
            jwt_secret=self.jwt_secret,
            now=1_700_000_100,
        )

        with self.assertRaises(RefreshTokenInvalidError):
            refresh_access_token(
                self.repo,
                RefreshAccessTokenRequest(company_id=self.reg.company.id, refresh_token=login_res.refresh_token),
                jwt_secret=self.jwt_secret,
                now=1_700_000_200,
            )

    def test_refresh_rejects_expired_token(self):
        login_res = login_user(
            self.repo,
            LoginRequest(company_id=self.reg.company.id, email="refresh@example.com", password="Secret1!"),
            jwt_secret=self.jwt_secret,
            refresh_token_ttl_seconds=10,
            now=1_700_000_000,
        )

        with self.assertRaises(RefreshTokenInvalidError):
            refresh_access_token(
                self.repo,
                RefreshAccessTokenRequest(company_id=self.reg.company.id, refresh_token=login_res.refresh_token),
                jwt_secret=self.jwt_secret,
                now=1_700_000_020,
            )


if __name__ == "__main__":
    unittest.main()
