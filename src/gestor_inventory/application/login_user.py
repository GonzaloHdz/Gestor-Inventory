from dataclasses import dataclass
import json
import time
from typing import Protocol

from gestor_inventory.domain.errors import InvalidCredentialsError, ValidationError
from gestor_inventory.security.jwt import create_jwt_hs256
from gestor_inventory.security.password_hash import verify_password


class UserAuthRepository(Protocol):
    def get_user_for_login(self, *, company_id: int, email: str) -> dict | None: ...

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
class LoginRequest:
    company_id: int
    email: str
    password: str


@dataclass(frozen=True)
class LoginResponse:
    access_token: str


def login_user(
    repo: UserAuthRepository,
    req: LoginRequest,
    *,
    jwt_secret: str,
    access_token_ttl_seconds: int = 60 * 60,
    now: int | None = None,
) -> LoginResponse:
    company_id = _validate_company_id(req.company_id)
    email = _normalize_email(req.email)
    password = _validate_password(req.password)
    now_v = int(time.time()) if now is None else int(now)

    user = repo.get_user_for_login(company_id=company_id, email=email)
    if not user:
        repo.create_audit_log(
            company_id=company_id,
            branch_id=None,
            user_id=None,
            event_type="auth.login_attempt",
            created_at=now_v,
            metadata_json=json.dumps({"success": False, "email": email, "reason": "user_not_found"}, separators=(",", ":")),
        )
        raise InvalidCredentialsError()
    if not bool(user.get("is_active", True)):
        user_id = user.get("id")
        repo.create_audit_log(
            company_id=company_id,
            branch_id=None,
            user_id=int(user_id) if isinstance(user_id, int) else None,
            event_type="auth.login_attempt",
            created_at=now_v,
            metadata_json=json.dumps({"success": False, "email": email, "reason": "inactive"}, separators=(",", ":")),
        )
        raise InvalidCredentialsError()

    password_hash = user.get("password_hash")
    if not isinstance(password_hash, str) or not verify_password(password, password_hash):
        user_id = user.get("id")
        repo.create_audit_log(
            company_id=company_id,
            branch_id=None,
            user_id=int(user_id) if isinstance(user_id, int) else None,
            event_type="auth.login_attempt",
            created_at=now_v,
            metadata_json=json.dumps({"success": False, "email": email, "reason": "bad_password"}, separators=(",", ":")),
        )
        raise InvalidCredentialsError()

    user_id = user.get("id")
    token = create_jwt_hs256(
        {"sub": str(user_id), "company_id": company_id, "email": email},
        secret=jwt_secret,
        expires_in_seconds=access_token_ttl_seconds,
    )
    repo.create_audit_log(
        company_id=company_id,
        branch_id=None,
        user_id=int(user_id) if isinstance(user_id, int) else None,
        event_type="auth.login_attempt",
        created_at=now_v,
        metadata_json=json.dumps({"success": True, "email": email}, separators=(",", ":")),
    )
    return LoginResponse(access_token=token)


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


def _validate_password(password: str) -> str:
    if not isinstance(password, str) or not password:
        raise ValidationError("password inválido")
    return password
