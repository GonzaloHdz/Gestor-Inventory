from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.errors import InvalidCredentialsError, ValidationError
from gestor_inventory.security.jwt import create_jwt_hs256
from gestor_inventory.security.password_hash import verify_password


class UserAuthRepository(Protocol):
    def get_user_for_login(self, *, company_id: int, email: str) -> dict | None: ...


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
) -> LoginResponse:
    company_id = _validate_company_id(req.company_id)
    email = _normalize_email(req.email)
    password = _validate_password(req.password)

    user = repo.get_user_for_login(company_id=company_id, email=email)
    if not user:
        raise InvalidCredentialsError()
    if not bool(user.get("is_active", True)):
        raise InvalidCredentialsError()

    password_hash = user.get("password_hash")
    if not isinstance(password_hash, str) or not verify_password(password, password_hash):
        raise InvalidCredentialsError()

    user_id = user.get("id")
    token = create_jwt_hs256(
        {"sub": str(user_id), "company_id": company_id, "email": email},
        secret=jwt_secret,
        expires_in_seconds=access_token_ttl_seconds,
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
