from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.errors import ValidationError
from gestor_inventory.domain.operational import Branch


class BranchListRepository(Protocol):
    def list_branches(self, *, company_id: int, city: str | None, status: str | None) -> list[Branch]: ...


@dataclass(frozen=True)
class ListBranchesRequest:
    company_id: int
    city: str | None = None
    status: str | None = None


@dataclass(frozen=True)
class ListBranchesResponse:
    branches: list[Branch]


def list_branches(repo: BranchListRepository, req: ListBranchesRequest) -> ListBranchesResponse:
    company_id = _validate_company_id(req.company_id)
    city = _normalize_optional(req.city)
    status = _validate_status(req.status)
    branches = repo.list_branches(company_id=company_id, city=city, status=status)
    return ListBranchesResponse(branches=branches)


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _normalize_optional(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError("city inválido")
    v = value.strip()
    return v or None


def _validate_status(status: str | None) -> str | None:
    if status is None:
        return None
    if not isinstance(status, str):
        raise ValidationError("status inválido")
    v = status.strip().lower()
    if v not in ("active", "inactive"):
        raise ValidationError("status inválido")
    return v
