from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.errors import EmailAlreadyExistsError, ForbiddenError, NotFoundError, ValidationError
from gestor_inventory.domain.user import User
from gestor_inventory.security.password_hash import hash_password
from gestor_inventory.security.password_policy import validate_password_strength


@dataclass(frozen=True)
class UserDetails:
    id: int
    company_id: int
    email: str
    is_active: bool
    verified: bool
    roles: list[str]


class ManageUsersRepository(Protocol):
    def user_belongs_to_company(self, *, company_id: int, user_id: int) -> bool: ...

    def get_user_by_id(self, *, company_id: int, user_id: int) -> User | None: ...

    def get_user_id_by_email(self, *, company_id: int, email: str) -> int | None: ...

    def list_user_role_names(self, *, company_id: int, user_id: int) -> list[str]: ...

    def update_user(
        self,
        *,
        company_id: int,
        user_id: int,
        email: str | None,
        password_hash: str | None,
        is_active: bool | None,
        verified: bool | None,
    ) -> User: ...

    def deactivate_user(self, *, company_id: int, user_id: int) -> str: ...


@dataclass(frozen=True)
class GetUserRequest:
    company_id: int
    user_id: int


@dataclass(frozen=True)
class GetUserResponse:
    user: UserDetails


@dataclass(frozen=True)
class UpdateUserRequest:
    company_id: int
    actor_user_id: int
    user_id: int
    email: str | None = None
    password: str | None = None
    is_active: bool | None = None
    verified: bool | None = None


@dataclass(frozen=True)
class UpdateUserResponse:
    user: UserDetails


@dataclass(frozen=True)
class DeleteUserRequest:
    company_id: int
    actor_user_id: int
    user_id: int


@dataclass(frozen=True)
class DeleteUserResponse:
    changed: bool


def get_user(repo: ManageUsersRepository, req: GetUserRequest) -> GetUserResponse:
    company_id = _validate_company_id(req.company_id)
    user_id = _validate_user_id(req.user_id)
    user = _get_required_user(repo, company_id=company_id, user_id=user_id)
    return GetUserResponse(user=_build_user_details(repo, user))


def update_user(repo: ManageUsersRepository, req: UpdateUserRequest) -> UpdateUserResponse:
    company_id = _validate_company_id(req.company_id)
    actor_user_id = _validate_user_id(req.actor_user_id, field="actor_user_id")
    user_id = _validate_user_id(req.user_id)
    _assert_user_exists(repo, company_id=company_id, user_id=actor_user_id, message="actor no encontrado")
    target_user = _get_required_user(repo, company_id=company_id, user_id=user_id)
    _assert_actor_can_manage_target(repo, company_id=company_id, actor_user_id=actor_user_id, target_user_id=user_id)

    email = _normalize_optional_email(req.email)
    if email is not None:
        existing_user_id = repo.get_user_id_by_email(company_id=company_id, email=email)
        if existing_user_id is not None and int(existing_user_id) != int(target_user.id):
            raise EmailAlreadyExistsError()

    password_hash = _hash_optional_password(req.password)
    is_active = _validate_optional_bool(req.is_active, field="is_active")
    verified = _validate_optional_bool(req.verified, field="verified")

    if email is None and password_hash is None and is_active is None and verified is None:
        raise ValidationError("No hay cambios para aplicar")
    if int(actor_user_id) == int(user_id) and is_active is False:
        raise ForbiddenError("No puedes desactivar tu propio usuario")

    updated_user = repo.update_user(
        company_id=company_id,
        user_id=user_id,
        email=email,
        password_hash=password_hash,
        is_active=is_active,
        verified=verified,
    )
    return UpdateUserResponse(user=_build_user_details(repo, updated_user))


def delete_user(repo: ManageUsersRepository, req: DeleteUserRequest) -> DeleteUserResponse:
    company_id = _validate_company_id(req.company_id)
    actor_user_id = _validate_user_id(req.actor_user_id, field="actor_user_id")
    user_id = _validate_user_id(req.user_id)
    _assert_user_exists(repo, company_id=company_id, user_id=actor_user_id, message="actor no encontrado")
    _get_required_user(repo, company_id=company_id, user_id=user_id)
    if int(actor_user_id) == int(user_id):
        raise ForbiddenError("No puedes eliminar tu propio usuario")
    _assert_actor_can_manage_target(repo, company_id=company_id, actor_user_id=actor_user_id, target_user_id=user_id)

    status = repo.deactivate_user(company_id=company_id, user_id=user_id)
    if status == "not_found":
        raise NotFoundError("usuario no encontrado")
    return DeleteUserResponse(changed=(status == "changed"))


def _build_user_details(repo: ManageUsersRepository, user: User) -> UserDetails:
    return UserDetails(
        id=int(user.id),
        company_id=int(user.company_id),
        email=str(user.email),
        is_active=bool(user.is_active),
        verified=bool(user.verified),
        roles=list(repo.list_user_role_names(company_id=int(user.company_id), user_id=int(user.id))),
    )


def _get_required_user(repo: ManageUsersRepository, *, company_id: int, user_id: int) -> User:
    user = repo.get_user_by_id(company_id=company_id, user_id=user_id)
    if user is None:
        raise NotFoundError("usuario no encontrado")
    return user


def _assert_user_exists(repo: ManageUsersRepository, *, company_id: int, user_id: int, message: str) -> None:
    if not repo.user_belongs_to_company(company_id=company_id, user_id=user_id):
        raise NotFoundError(message)


def _assert_actor_can_manage_target(
    repo: ManageUsersRepository,
    *,
    company_id: int,
    actor_user_id: int,
    target_user_id: int,
) -> None:
    actor_role_names = set(repo.list_user_role_names(company_id=company_id, user_id=actor_user_id))
    if "Superadministrador" in actor_role_names:
        return

    target_role_names = set(repo.list_user_role_names(company_id=company_id, user_id=target_user_id))
    if "Superadministrador" in target_role_names:
        raise ForbiddenError("No puedes gestionar un Superadministrador")

    if "Administrador" in actor_role_names:
        return

    if "Supervisor" in actor_role_names:
        if "Supervisor" in target_role_names or "Administrador" in target_role_names:
            raise ForbiddenError("Un Supervisor no puede gestionar a otros Supervisores ni Administradores")
        if "Almacenista" not in target_role_names:
            raise ForbiddenError("Un Supervisor solo puede gestionar usuarios con rol Almacenista")
        return

    raise ForbiddenError("No tienes permisos para gestionar usuarios")


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_user_id(user_id: int, *, field: str = "user_id") -> int:
    if not isinstance(user_id, int) or user_id <= 0:
        raise ValidationError(f"{field} inválido")
    return user_id


def _normalize_optional_email(email: str | None) -> str | None:
    if email is None:
        return None
    if not isinstance(email, str):
        raise ValidationError("email inválido")
    normalized = email.strip().lower()
    if not normalized or "@" not in normalized:
        raise ValidationError("email inválido")
    return normalized


def _hash_optional_password(password: str | None) -> str | None:
    if password is None:
        return None
    validate_password_strength(password)
    return hash_password(str(password))


def _validate_optional_bool(value: bool | None, *, field: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ValidationError(f"{field} inválido")
    return bool(value)
