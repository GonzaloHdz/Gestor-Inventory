import os
import sys
import unittest
from urllib.parse import parse_qs, urlparse

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

from gestor_inventory.application.register_user import RegisterUserRequest, register_user
from gestor_inventory.application.resend_verification_email import (
    ResendVerificationEmailRequest,
    resend_verification_email,
)
from gestor_inventory.infrastructure.sqlite_user_repository import SqliteUserRepository


class ResendVerificationEmailTests(unittest.TestCase):
    def setUp(self):
        self.repo = SqliteUserRepository(":memory:")

    def test_resend_generates_new_verification_url_for_pending_user(self):
        reg = register_user(
            self.repo,
            RegisterUserRequest(email="pending@example.com", password="Secret1!", company_name="Pending Co"),
            base_url="http://localhost:8000",
            now=1_000_000,
        )

        res = resend_verification_email(
            self.repo,
            ResendVerificationEmailRequest(company_id=reg.company.id, email="pending@example.com"),
            base_url="http://localhost:8000",
            now=1_000_100,
        )

        self.assertTrue(res.sent)
        self.assertIsNotNone(res.verification_url)
        parsed = urlparse(str(res.verification_url))
        params = parse_qs(parsed.query)
        self.assertEqual(parsed.path, "/api/auth/verify")
        self.assertTrue(params["token"][0].startswith(f"{reg.company.id}."))

    def test_resend_returns_not_sent_for_verified_user(self):
        reg = register_user(
            self.repo,
            RegisterUserRequest(email="verified@example.com", password="Secret1!", company_name="Verified Co"),
        )
        self.repo._persistent_conn.execute(
            "UPDATE users SET verified = 1 WHERE company_id = ? AND id = ?",
            (reg.company.id, reg.user.id),
        )
        self.repo._persistent_conn.commit()

        res = resend_verification_email(
            self.repo,
            ResendVerificationEmailRequest(company_id=reg.company.id, email="verified@example.com"),
        )

        self.assertFalse(res.sent)
        self.assertIsNone(res.verification_url)

    def test_resend_returns_not_sent_for_unknown_user(self):
        res = resend_verification_email(
            self.repo,
            ResendVerificationEmailRequest(company_id=1, email="missing@example.com"),
        )
        self.assertFalse(res.sent)
        self.assertIsNone(res.verification_url)


if __name__ == "__main__":
    unittest.main()
