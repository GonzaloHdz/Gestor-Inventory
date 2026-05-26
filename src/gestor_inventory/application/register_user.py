from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.errors import EmailAlreadyExistsError, ValidationError
from gestor_inventory.domain.user import User
from gestor_inventory.security.password_hash import hash_password


class UserRepository(Protocol):
    def email_exists(self, *, company_id: int, email: str) -> bool: ...

    def create_user_with_role(
        self,
        *,
        company_id: int,
        email: str,
        password_hash: str,
        role_id: int,
    ) -> tuple[User, int]: ...


@dataclass(frozen=True)
class RegisterUserRequest:
    company_id: int
    email: str
    password: str
    role_id: int


@dataclass(frozen=True)
class RegisterUserResponse:
    user: User
    role_id: int


def register_user(repo: UserRepository, req: RegisterUserRequest) -> RegisterUserResponse:
    company_id = _validate_company_id(req.company_id)
    email = _normalize_email(req.email)
    password = _validate_password(req.password)
    role_id = _validate_role_id(req.role_id)

    if repo.email_exists(company_id=company_id, email=email):
        raise EmailAlreadyExistsError()

    password_hash = hash_password(password)
    user, role_id = repo.create_user_with_role(
        company_id=company_id,
        email=email,
        password_hash=password_hash,
        role_id=role_id,
    )
    return RegisterUserResponse(user=user, role_id=role_id)


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_role_id(role_id: int) -> int:
    if not isinstance(role_id, int) or role_id <= 0:
        raise ValidationError("role_id inválido")
    return role_id


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
