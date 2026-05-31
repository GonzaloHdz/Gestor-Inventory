import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.errors import ValidationError


class PasswordResetRepository(Protocol):
    def get_user_id_by_email(self, *, company_id: int, email: str) -> int | None: ...

    def create_audit_log(
        self,
        *,
        company_id: int,
        branch_id: int | None,
        user_id: int | None,
        event_type: str,
        created_at: int,
        metadata_json: str | None,
    ) -> None: ...

    def create_password_reset_token(
        self,
        *,
        company_id: int,
        user_id: int,
        token_hash: str,
        expires_at: int,
        created_at: int,
    ) -> None: ...


@dataclass(frozen=True)
class RequestPasswordResetRequest:
    company_id: int
    email: str


@dataclass(frozen=True)
class RequestPasswordResetResponse:
    reset_token: str | None
    reset_url: str | None


def request_password_reset(
    repo: PasswordResetRepository,
    req: RequestPasswordResetRequest,
    *,
    token_ttl_seconds: int = 15 * 60,
    base_url: str = "https://example.com",
    now: int | None = None,
) -> RequestPasswordResetResponse:
    company_id = _validate_company_id(req.company_id)
    email = _normalize_email(req.email)
    now_v = int(time.time()) if now is None else int(now)

    user_id = repo.get_user_id_by_email(company_id=company_id, email=email)
    if user_id is None:
        repo.create_audit_log(
            company_id=company_id,
            branch_id=None,
            user_id=None,
            event_type="auth.password_reset_requested",
            created_at=now_v,
            metadata_json=json.dumps({"email": email, "user_found": False}, separators=(",", ":")),
        )
        return RequestPasswordResetResponse(reset_token=None, reset_url=None)

    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    expires_at = now_v + int(token_ttl_seconds)
    repo.create_password_reset_token(
        company_id=company_id,
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at,
        created_at=now_v,
    )

    repo.create_audit_log(
        company_id=company_id,
        branch_id=None,
        user_id=int(user_id),
        event_type="auth.password_reset_requested",
        created_at=now_v,
        metadata_json=json.dumps({"email": email, "user_found": True}, separators=(",", ":")),
    )
    reset_url = f"{base_url.rstrip('/')}/reset-password?company_id={company_id}&token={token}"
    return RequestPasswordResetResponse(reset_token=token, reset_url=reset_url)


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
