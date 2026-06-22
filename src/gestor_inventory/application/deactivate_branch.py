from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.errors import BranchHasInventoryError, NotFoundError, ValidationError


class BranchDeactivateRepository(Protocol):
    def branch_has_inventory(self, *, company_id: int, branch_id: int) -> bool: ...

    def deactivate_branch(self, *, company_id: int, branch_id: int) -> str: ...


@dataclass(frozen=True)
class DeactivateBranchRequest:
    company_id: int
    branch_id: int


@dataclass(frozen=True)
class DeactivateBranchResponse:
    changed: bool


def deactivate_branch(repo: BranchDeactivateRepository, req: DeactivateBranchRequest) -> DeactivateBranchResponse:
    company_id = _validate_company_id(req.company_id)
    branch_id = _validate_branch_id(req.branch_id)

    if repo.branch_has_inventory(company_id=company_id, branch_id=branch_id):
        raise BranchHasInventoryError()

    status = repo.deactivate_branch(company_id=company_id, branch_id=branch_id)
    if status == "not_found":
        raise NotFoundError("sucursal no encontrada")
    if status == "already_inactive":
        return DeactivateBranchResponse(changed=False)
    if status == "changed":
        return DeactivateBranchResponse(changed=True)
    raise ValidationError("operación inválida")


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_branch_id(branch_id: int) -> int:
    if not isinstance(branch_id, int) or branch_id <= 0:
        raise ValidationError("branch_id inválido")
    return branch_id
