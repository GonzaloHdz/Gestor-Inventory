from dataclasses import dataclass
import hashlib
import secrets
import time
from typing import Protocol

from gestor_inventory.domain.errors import ValidationError
from gestor_inventory.application.verification_links import build_verification_url


class ResendVerificationRepository(Protocol):
    def get_user_for_verification(self, *, company_id: int, email: str) -> dict | None: ...

    def create_email_verification_token(
        self,
        *,
        company_id: int,
        user_id: int,
        token_hash: str,
        expires_at: int,
        created_at: int,
    ) -> None: ...


@dataclass(frozen=True)
class ResendVerificationEmailRequest:
    company_id: int
    email: str


@dataclass(frozen=True)
class ResendVerificationEmailResponse:
    sent: bool
    verification_url: str | None = None


def resend_verification_email(
    repo: ResendVerificationRepository,
    req: ResendVerificationEmailRequest,
    *,
    verification_token_ttl_seconds: int = 24 * 60 * 60,
    base_url: str = "https://example.com",
    now: int | None = None,
) -> ResendVerificationEmailResponse:
    company_id = _validate_company_id(req.company_id)
    email = _normalize_email(req.email)
    now_v = int(time.time()) if now is None else int(now)

    user = repo.get_user_for_verification(company_id=company_id, email=email)
    if not user:
        return ResendVerificationEmailResponse(sent=False)
    if bool(user.get("verified", False)):
        return ResendVerificationEmailResponse(sent=False)
    if not bool(user.get("is_active", True)):
        return ResendVerificationEmailResponse(sent=False)

    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    repo.create_email_verification_token(
        company_id=company_id,
        user_id=int(user["id"]),
        token_hash=token_hash,
        expires_at=now_v + int(verification_token_ttl_seconds),
        created_at=now_v,
    )
    verification_url = build_verification_url(base_url=base_url, company_id=company_id, raw_token=token)
    return ResendVerificationEmailResponse(sent=True, verification_url=verification_url)


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _normalize_email(email: str) -> str:
    if not isinstance(email, str):
        raise ValidationError("email inválido")
    normalized = email.strip().lower()
    if not normalized or "@" not in normalized:
        raise ValidationError("email inválido")
    return normalized
