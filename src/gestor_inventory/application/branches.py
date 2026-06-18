from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.errors import CrossTenantReferenceError, ValidationError
from gestor_inventory.domain.operational import Branch


class BranchRepository(Protocol):
    def company_is_active(self, *, company_id: int) -> bool: ...

    def create_branch(
        self,
        *,
        company_id: int,
        name: str,
        address: str | None,
        city: str | None,
        country: str | None,
        status: str,
        is_active: bool,
    ) -> Branch: ...


@dataclass(frozen=True)
class CreateBranchRequest:
    company_id: int
    name: str
    address: str | None = None
    city: str | None = None
    country: str | None = None


@dataclass(frozen=True)
class CreateBranchResponse:
    branch: Branch


def create_branch(repo: BranchRepository, req: CreateBranchRequest) -> CreateBranchResponse:
    company_id = _validate_company_id(req.company_id)
    name = _validate_name(req.name)
    address = _normalize_optional(req.address)
    city = _normalize_optional(req.city)
    country = _normalize_optional(req.country)

    if not repo.company_is_active(company_id=company_id):
        raise CrossTenantReferenceError("empresa inválida")

    branch = repo.create_branch(
        company_id=company_id,
        name=name,
        address=address,
        city=city,
        country=country,
        status="active",
        is_active=True,
    )
    return CreateBranchResponse(branch=branch)


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_name(name: str) -> str:
    if not isinstance(name, str):
        raise ValidationError("name inválido")
    v = name.strip()
    if not v:
        raise ValidationError("name inválido")
    return v


def _normalize_optional(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError("address inválido")
    v = value.strip()
    return v or None
