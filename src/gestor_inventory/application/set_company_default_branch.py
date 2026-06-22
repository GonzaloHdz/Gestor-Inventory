from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.errors import CrossTenantReferenceError, ValidationError


class CompanyDefaultBranchRepository(Protocol):
    def company_is_active(self, *, company_id: int) -> bool: ...

    def branch_belongs_to_company(self, *, company_id: int, branch_id: int) -> bool: ...

    def get_branch_by_id(self, *, company_id: int, branch_id: int) -> object | None: ...

    def update_company_default_branch(self, *, company_id: int, default_branch_id: int | None) -> None: ...


@dataclass(frozen=True)
class SetCompanyDefaultBranchRequest:
    company_id: int
    default_branch_id: int | None


def set_company_default_branch(repo: CompanyDefaultBranchRepository, req: SetCompanyDefaultBranchRequest) -> None:
    company_id = _validate_company_id(req.company_id)
    default_branch_id = _validate_optional_id(req.default_branch_id)

    if not repo.company_is_active(company_id=company_id):
        raise CrossTenantReferenceError("empresa inválida")

    if default_branch_id is not None:
        if not repo.branch_belongs_to_company(company_id=company_id, branch_id=default_branch_id):
            raise CrossTenantReferenceError("default_branch_id no pertenece a la empresa")
        branch = repo.get_branch_by_id(company_id=company_id, branch_id=default_branch_id)
        if branch is None or getattr(branch, "status", None) != "active":
            raise CrossTenantReferenceError("sucursal inválida")

    repo.update_company_default_branch(company_id=company_id, default_branch_id=default_branch_id)


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_optional_id(value: int | None) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or value <= 0:
        raise ValidationError("default_branch_id inválido")
    return value
