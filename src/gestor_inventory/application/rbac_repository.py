from typing import Protocol

from gestor_inventory.domain.rbac import Permission, Role


class RoleRepository(Protocol):
    def get_role(self, *, company_id: int, role_id: int) -> Role | None: ...

    def list_roles(self, *, company_id: int) -> list[Role]: ...


class PermissionRepository(Protocol):
    def get_permission_by_code(self, *, code: str) -> Permission | None: ...

    def list_permissions(self) -> list[Permission]: ...

