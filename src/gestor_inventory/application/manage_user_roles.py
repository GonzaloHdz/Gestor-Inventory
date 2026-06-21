from dataclasses import dataclass

from gestor_inventory.application.rbac_repository import UserRoleRepository
from gestor_inventory.domain.errors import ForbiddenError, NotFoundError, ValidationError


@dataclass(frozen=True)
class AssignUserRoleRequest:
    company_id: int
    actor_user_id: int
    user_id: int
    role_id: int


@dataclass(frozen=True)
class RevokeUserRoleRequest:
    company_id: int
    actor_user_id: int
    user_id: int
    role_id: int


@dataclass(frozen=True)
class UserRoleChangeResponse:
    changed: bool


def assign_user_role(repo: UserRoleRepository, req: AssignUserRoleRequest) -> UserRoleChangeResponse:
    company_id = _validate_company_id(req.company_id)
    actor_user_id = _validate_user_id(req.actor_user_id, field="actor_user_id")
    user_id = _validate_user_id(req.user_id)
    role_id = _validate_role_id(req.role_id)

    if not repo.user_belongs_to_company(company_id=company_id, user_id=actor_user_id):
        raise NotFoundError("actor no encontrado")
    if not repo.user_belongs_to_company(company_id=company_id, user_id=user_id):
        raise NotFoundError("usuario no encontrado")
    if not repo.role_belongs_to_company(company_id=company_id, role_id=role_id):
        raise NotFoundError("rol no encontrado")

    _assert_actor_can_manage_role(repo, company_id=company_id, actor_user_id=actor_user_id, target_user_id=user_id, role_id=role_id)
    changed = repo.assign_role_to_user(company_id=company_id, user_id=user_id, role_id=role_id)
    return UserRoleChangeResponse(changed=bool(changed))


def revoke_user_role(repo: UserRoleRepository, req: RevokeUserRoleRequest) -> UserRoleChangeResponse:
    company_id = _validate_company_id(req.company_id)
    actor_user_id = _validate_user_id(req.actor_user_id, field="actor_user_id")
    user_id = _validate_user_id(req.user_id)
    role_id = _validate_role_id(req.role_id)

    if not repo.user_belongs_to_company(company_id=company_id, user_id=actor_user_id):
        raise NotFoundError("actor no encontrado")
    if not repo.user_belongs_to_company(company_id=company_id, user_id=user_id):
        raise NotFoundError("usuario no encontrado")
    if not repo.role_belongs_to_company(company_id=company_id, role_id=role_id):
        raise NotFoundError("rol no encontrado")

    _assert_actor_can_manage_role(repo, company_id=company_id, actor_user_id=actor_user_id, target_user_id=user_id, role_id=role_id)
    changed = repo.revoke_role_from_user(company_id=company_id, user_id=user_id, role_id=role_id)
    return UserRoleChangeResponse(changed=bool(changed))


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_user_id(user_id: int, *, field: str = "user_id") -> int:
    if not isinstance(user_id, int) or user_id <= 0:
        raise ValidationError(f"{field} inválido")
    return user_id


def _validate_role_id(role_id: int) -> int:
    if not isinstance(role_id, int) or role_id <= 0:
        raise ValidationError("role_id inválido")
    return role_id


def _assert_actor_can_manage_role(
    repo: UserRoleRepository,
    *,
    company_id: int,
    actor_user_id: int,
    target_user_id: int,
    role_id: int,
) -> None:
    target_role = repo.get_role(company_id=company_id, role_id=role_id)
    if target_role is None:
        raise NotFoundError("rol no encontrado")

    actor_role_names = set(repo.list_user_role_names(company_id=company_id, user_id=actor_user_id))
    if "Superadministrador" in actor_role_names:
        return
    if "Administrador" not in actor_role_names:
        raise ForbiddenError("No tienes permisos para modificar roles")
    if actor_user_id == target_user_id:
        raise ForbiddenError("No puedes modificar tus propios roles")

    target_user_role_names = set(repo.list_user_role_names(company_id=company_id, user_id=target_user_id))
    if "Superadministrador" in target_user_role_names:
        raise ForbiddenError("No puedes modificar roles de un Superadministrador")
    if target_role.name == "Superadministrador":
        raise ForbiddenError("No puedes asignar o revocar el rol Superadministrador")
