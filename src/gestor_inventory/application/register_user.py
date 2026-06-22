from dataclasses import dataclass
import hashlib
import secrets
import time
from typing import Protocol

from gestor_inventory.domain.company import Company
from gestor_inventory.domain.errors import CompanyNameAlreadyExistsError, EmailAlreadyExistsError, ValidationError
from gestor_inventory.domain.user import User
from gestor_inventory.security.password_hash import hash_password
from gestor_inventory.security.password_policy import validate_password_strength
from gestor_inventory.application.verification_links import build_verification_url


class UserRepository(Protocol):
    def company_name_exists(self, *, name: str) -> bool: ...

    def create_company(self, *, name: str, currency: str, timezone: str, created_at: int) -> Company: ...

    def email_exists(self, *, company_id: int, email: str) -> bool: ...

    def create_user_with_role(
        self,
        *,
        company_id: int,
        email: str,
        password_hash: str,
        role_id: int,
    ) -> tuple[User, int]: ...

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
class RegisterUserRequest:
    email: str
    password: str
    company_name: str | None = None
    currency: str = "USD"
    timezone: str = "UTC"


@dataclass(frozen=True)
class RegisterUserResponse:
    company: Company
    user: User
    role_id: int
    verification_url: str


OWNER_ROLE_ID = 12


def register_user(
    repo: UserRepository,
    req: RegisterUserRequest,
    *,
    verification_token_ttl_seconds: int = 24 * 60 * 60,
    base_url: str = "https://example.com",
    now: int | None = None,
) -> RegisterUserResponse:
    email = _normalize_email(req.email)
    password = _validate_password(req.password)
    company_name = _resolve_company_name(repo, req.company_name, email=email)
    currency = _validate_currency(req.currency)
    timezone = _validate_timezone(req.timezone)
    now_v = int(time.time()) if now is None else int(now)

    company = repo.create_company(name=company_name, currency=currency, timezone=timezone, created_at=now_v)
    company_id = int(company.id)
    if repo.email_exists(company_id=company_id, email=email):
        raise EmailAlreadyExistsError()

    password_hash = hash_password(password)
    user, role_id = repo.create_user_with_role(
        company_id=company_id,
        email=email,
        password_hash=password_hash,
        role_id=OWNER_ROLE_ID,
    )

    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    expires_at = now_v + int(verification_token_ttl_seconds)
    repo.create_email_verification_token(
        company_id=company_id,
        user_id=int(user.id),
        token_hash=token_hash,
        expires_at=expires_at,
        created_at=now_v,
    )
    verification_url = build_verification_url(base_url=base_url, company_id=company_id, raw_token=token)
    return RegisterUserResponse(company=company, user=user, role_id=role_id, verification_url=verification_url)


def _normalize_email(email: str) -> str:
    if not isinstance(email, str):
        raise ValidationError("email inválido")
    normalized = email.strip().lower()
    if not normalized or "@" not in normalized:
        raise ValidationError("email inválido")
    return normalized


def _validate_password(password: str) -> str:
    validate_password_strength(password)
    return str(password)


def _resolve_company_name(repo: UserRepository, company_name: str | None, *, email: str) -> str:
    if company_name is not None:
        name = _validate_company_name(company_name)
        if repo.company_name_exists(name=name):
            raise CompanyNameAlreadyExistsError()
        return name

    local_part = email.split("@", 1)[0].strip() or "usuario"
    base_name = _validate_company_name(f"Empresa de {local_part}")
    if not repo.company_name_exists(name=base_name):
        return base_name

    suffix = 2
    while True:
        candidate = _validate_company_name(f"{base_name} {suffix}")
        if not repo.company_name_exists(name=candidate):
            return candidate
        suffix += 1


def _validate_company_name(company_name: str) -> str:
    if not isinstance(company_name, str):
        raise ValidationError("company_name inválido")
    value = company_name.strip()
    if not value:
        raise ValidationError("company_name inválido")
    return value


def _validate_currency(currency: str) -> str:
    if not isinstance(currency, str):
        raise ValidationError("currency inválido")
    value = currency.strip().upper()
    if not value or len(value) > 8:
        raise ValidationError("currency inválido")
    return value


def _validate_timezone(timezone: str) -> str:
    if not isinstance(timezone, str):
        raise ValidationError("timezone inválido")
    value = timezone.strip()
    if not value:
        raise ValidationError("timezone inválido")
    return value
