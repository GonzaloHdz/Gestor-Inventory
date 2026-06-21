from dataclasses import dataclass
import hashlib
import secrets
import time
from typing import Protocol

from gestor_inventory.domain.errors import EmailAlreadyExistsError, ForbiddenError, NotFoundError, ValidationError
from gestor_inventory.domain.rbac import Role
from gestor_inventory.domain.user import User
from gestor_inventory.security.password_hash import hash_password
from gestor_inventory.security.password_policy import validate_password_strength


class InternalUserRepository(Protocol):
    def email_exists(self, *, company_id: int, email: str) -> bool: ...

    def get_role(self, *, company_id: int, role_id: int) -> Role | None: ...

    def list_user_role_names(self, *, company_id: int, user_id: int) -> list[str]: ...

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
class CreateInternalUserRequest:
    company_id: int
    actor_user_id: int
    email: str
    password: str
    role_id: int


@dataclass(frozen=True)
class CreateInternalUserResponse:
    user: User
    role_id: int
    verification_url: str


def create_internal_user(
    repo: InternalUserRepository,
    req: CreateInternalUserRequest,
    *,
    verification_token_ttl_seconds: int = 24 * 60 * 60,
    base_url: str = "https://example.com",
    now: int | None = None,
) -> CreateInternalUserResponse:
    company_id = _validate_company_id(req.company_id)
    actor_user_id = _validate_user_id(req.actor_user_id, field="actor_user_id")
    email = _normalize_email(req.email)
    password = _validate_password(req.password)
    role_id = _validate_user_id(req.role_id, field="role_id")
    now_v = int(time.time()) if now is None else int(now)

    _assert_actor_can_create_role(repo, company_id=company_id, actor_user_id=actor_user_id, role_id=role_id)

    if repo.email_exists(company_id=company_id, email=email):
        raise EmailAlreadyExistsError()

    password_hash = hash_password(password)
    user, assigned_role_id = repo.create_user_with_role(
        company_id=company_id,
        email=email,
        password_hash=password_hash,
        role_id=role_id,
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
    verification_url = f"{base_url.rstrip('/')}/api/auth/verify-email?company_id={company_id}&token={token}"
    return CreateInternalUserResponse(user=user, role_id=assigned_role_id, verification_url=verification_url)


def _assert_actor_can_create_role(
    repo: InternalUserRepository, *, company_id: int, actor_user_id: int, role_id: int
) -> None:
    target_role = repo.get_role(company_id=company_id, role_id=role_id)
    if target_role is None:
        raise NotFoundError("rol no encontrado")

    actor_role_names = set(repo.list_user_role_names(company_id=company_id, user_id=actor_user_id))
    if "Superadministrador" in actor_role_names:
        return
    if "Administrador" not in actor_role_names:
        raise ForbiddenError("No tienes permisos para crear usuarios")
    if target_role.name == "Superadministrador":
        raise ForbiddenError("No puedes crear usuarios con rol Superadministrador")


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_user_id(value: int, *, field: str) -> int:
    if not isinstance(value, int) or value <= 0:
        raise ValidationError(f"{field} inválido")
    return value


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
