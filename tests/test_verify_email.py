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
        company = self.repo.create_company(name="Verify One", currency="USD", timezone="UTC", created_at=1_000_000)
        user, _ = self.repo.create_user_with_role(
            company_id=company.id,
            email="user@example.com",
            password_hash="some-hash",
            role_id=12,
        )
        import secrets
        import hashlib
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        self.repo.create_email_verification_token(
            company_id=company.id,
            user_id=user.id,
            token_hash=token_hash,
            expires_at=1_000_020,
            created_at=1_000_000,
        )
        from gestor_inventory.application.verification_links import build_verification_url
        url = build_verification_url(base_url="https://example.com", company_id=company.id, raw_token=token)
        parsed = urlparse(url)
        combined_token = parse_qs(parsed.query)["token"][0]

        verify_email(self.repo, VerifyEmailRequest(token=combined_token), now=1_000_010)

        user_db = self.repo.get_user_for_login(company_id=company.id, email="user@example.com")
        self.assertIsNotNone(user_db)
        self.assertTrue(user_db["verified"])

    def test_verify_email_old_format_is_isolated_by_company(self):
        company = self.repo.create_company(name="Verify Two", currency="USD", timezone="UTC", created_at=1_000_000)
        user, _ = self.repo.create_user_with_role(
            company_id=company.id,
            email="user@example.com",
            password_hash="some-hash",
            role_id=12,
        )
        import secrets
        import hashlib
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        self.repo.create_email_verification_token(
            company_id=company.id,
            user_id=user.id,
            token_hash=token_hash,
            expires_at=1_000_020,
            created_at=1_000_000,
        )

        with self.assertRaises(ValidationError):
            verify_email(self.repo, VerifyEmailRequest(company_id=company.id + 1, token=token), now=1_000_010)

        user_db = self.repo.get_user_for_login(company_id=company.id, email="user@example.com")
        self.assertIsNotNone(user_db)
        self.assertFalse(user_db["verified"])


if __name__ == "__main__":
    unittest.main()
