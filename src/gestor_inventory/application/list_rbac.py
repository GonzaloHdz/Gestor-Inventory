from dataclasses import dataclass

from gestor_inventory.application.rbac_repository import PermissionRepository, RoleRepository
from gestor_inventory.domain.errors import ValidationError
from gestor_inventory.domain.rbac import Permission, Role


@dataclass(frozen=True)
class ListRolesRequest:
    company_id: int


@dataclass(frozen=True)
class ListRolesResponse:
    roles: list[Role]


@dataclass(frozen=True)
class ListPermissionsResponse:
    permissions: list[Permission]


def list_roles(repo: RoleRepository, req: ListRolesRequest) -> ListRolesResponse:
    company_id = _validate_company_id(req.company_id)
    roles = repo.list_roles(company_id=company_id)
    return ListRolesResponse(roles=roles)


def list_permissions(repo: PermissionRepository) -> ListPermissionsResponse:
    permissions = repo.list_permissions()
    return ListPermissionsResponse(permissions=permissions)


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id
