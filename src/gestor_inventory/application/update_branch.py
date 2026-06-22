from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.errors import NotFoundError, ValidationError
from gestor_inventory.domain.operational import Branch


class BranchUpdateRepository(Protocol):
    def get_branch_by_id(self, *, company_id: int, branch_id: int) -> Branch | None: ...

    def update_branch(
        self,
        *,
        company_id: int,
        branch_id: int,
        name: str | None,
        address: str | None,
        city: str | None,
        country: str | None,
    ) -> Branch: ...


@dataclass(frozen=True)
class UpdateBranchRequest:
    company_id: int
    branch_id: int
    name: str | None = None
    address: str | None = None
    city: str | None = None
    country: str | None = None


@dataclass(frozen=True)
class UpdateBranchResponse:
    branch: Branch


def update_branch(repo: BranchUpdateRepository, req: UpdateBranchRequest) -> UpdateBranchResponse:
    company_id = _validate_company_id(req.company_id)
    branch_id = _validate_branch_id(req.branch_id)
    name = _normalize_optional(req.name)
    address = _normalize_optional(req.address)
    city = _normalize_optional(req.city)
    country = _normalize_optional(req.country)

    if name is None and address is None and city is None and country is None:
        raise ValidationError("no hay campos para actualizar")

    current = repo.get_branch_by_id(company_id=company_id, branch_id=branch_id)
    if current is None:
        raise NotFoundError("sucursal no encontrada")

    updated = repo.update_branch(
        company_id=company_id,
        branch_id=branch_id,
        name=name,
        address=address,
        city=city,
        country=country,
    )
    return UpdateBranchResponse(branch=updated)


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_branch_id(branch_id: int) -> int:
    if not isinstance(branch_id, int) or branch_id <= 0:
        raise ValidationError("branch_id inválido")
    return branch_id


def _normalize_optional(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError("campo inválido")
    v = value.strip()
    return v or None
