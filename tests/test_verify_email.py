import os
import sys
import unittest
from urllib.parse import parse_qs, urlparse

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

from gestor_inventory.application.register_user import RegisterUserRequest, register_user
from gestor_inventory.application.verify_email import VerifyEmailRequest, verify_email
from gestor_inventory.domain.errors import ValidationError
from gestor_inventory.infrastructure.sqlite_user_repository import SqliteUserRepository


class VerifyEmailTests(unittest.TestCase):
    def setUp(self):
        self.repo = SqliteUserRepository(":memory:")

    def test_verify_email_happy_path_marks_user_verified(self):
        reg = register_user(
            self.repo,
            RegisterUserRequest(company_id=1, email="user@example.com", password="Secret1!", role_id=10),
            now=1_000_000,
        )
        parsed = urlparse(reg.verification_url)
        token = parse_qs(parsed.query)["token"][0]

        verify_email(self.repo, VerifyEmailRequest(company_id=1, token=token), now=1_000_010)

        user = self.repo.get_user_for_login(company_id=1, email="user@example.com")
        self.assertIsNotNone(user)
        self.assertTrue(user["verified"])

    def test_verify_email_is_isolated_by_company(self):
        reg = register_user(
            self.repo,
            RegisterUserRequest(company_id=1, email="user@example.com", password="Secret1!", role_id=10),
            now=1_000_000,
        )
        parsed = urlparse(reg.verification_url)
        token = parse_qs(parsed.query)["token"][0]

        with self.assertRaises(ValidationError):
            verify_email(self.repo, VerifyEmailRequest(company_id=2, token=token), now=1_000_010)

        user = self.repo.get_user_for_login(company_id=1, email="user@example.com")
        self.assertIsNotNone(user)
        self.assertFalse(user["verified"])


if __name__ == "__main__":
    unittest.main()
