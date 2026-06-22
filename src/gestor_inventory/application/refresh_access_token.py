from dataclasses import dataclass
import hashlib
import json
import secrets
import time
from typing import Protocol

from gestor_inventory.domain.errors import RefreshTokenInvalidError, ValidationError
from gestor_inventory.security.jwt import create_jwt_hs256


class RefreshTokenRepository(Protocol):
    def consume_refresh_token(self, *, company_id: int, token_hash: str, now: int) -> tuple[str, int | None]: ...

    def get_user_for_refresh(self, *, company_id: int, user_id: int) -> dict | None: ...

    def create_refresh_token(
        self,
        *,
        company_id: int,
        user_id: int,
        token_hash: str,
        expires_at: int,
        created_at: int,
    ) -> None: ...

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


@dataclass(frozen=True)
class RefreshAccessTokenRequest:
    company_id: int
    refresh_token: str


@dataclass(frozen=True)
class RefreshAccessTokenResponse:
    access_token: str
    refresh_token: str


def refresh_access_token(
    repo: RefreshTokenRepository,
    req: RefreshAccessTokenRequest,
    *,
    jwt_secret: str,
    access_token_ttl_seconds: int = 60 * 60,
    refresh_token_ttl_seconds: int = 7 * 24 * 60 * 60,
    now: int | None = None,
) -> RefreshAccessTokenResponse:
    company_id = _validate_company_id(req.company_id)
    refresh_token = _validate_refresh_token(req.refresh_token)
    now_v = int(time.time()) if now is None else int(now)
    refresh_token_hash = _hash_token(refresh_token)

    status, user_id = repo.consume_refresh_token(company_id=company_id, token_hash=refresh_token_hash, now=now_v)
    if status != "ok" or user_id is None:
        repo.create_audit_log(
            company_id=company_id,
            branch_id=None,
            user_id=int(user_id) if isinstance(user_id, int) else None,
            event_type="auth.refresh_attempt",
            created_at=now_v,
            metadata_json=json.dumps({"success": False, "reason": status}, separators=(",", ":")),
        )
        raise RefreshTokenInvalidError()

    user = repo.get_user_for_refresh(company_id=company_id, user_id=int(user_id))
    if not user or not bool(user.get("is_active", True)) or not bool(user.get("verified", False)):
        repo.create_audit_log(
            company_id=company_id,
            branch_id=None,
            user_id=int(user_id),
            event_type="auth.refresh_attempt",
            created_at=now_v,
            metadata_json=json.dumps({"success": False, "reason": "invalid_user"}, separators=(",", ":")),
        )
        raise RefreshTokenInvalidError()

    email = str(user.get("email"))
    access_token = create_jwt_hs256(
        {"sub": str(user_id), "company_id": company_id, "email": email},
        secret=jwt_secret,
        expires_in_seconds=access_token_ttl_seconds,
    )
    new_refresh_token = secrets.token_urlsafe(32)
    repo.create_refresh_token(
        company_id=company_id,
        user_id=int(user_id),
        token_hash=_hash_token(new_refresh_token),
        expires_at=now_v + int(refresh_token_ttl_seconds),
        created_at=now_v,
    )
    repo.create_audit_log(
        company_id=company_id,
        branch_id=None,
        user_id=int(user_id),
        event_type="auth.refresh_attempt",
        created_at=now_v,
        metadata_json=json.dumps({"success": True}, separators=(",", ":")),
    )
    return RefreshAccessTokenResponse(access_token=access_token, refresh_token=new_refresh_token)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_refresh_token(refresh_token: str) -> str:
    if not isinstance(refresh_token, str):
        raise ValidationError("refresh_token inválido")
    value = refresh_token.strip()
    if not value:
        raise ValidationError("refresh_token inválido")
    return value
