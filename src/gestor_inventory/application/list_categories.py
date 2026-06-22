from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.errors import ValidationError
from gestor_inventory.domain.operational import Category


class CategoryListRepository(Protocol):
    def list_categories(self, *, company_id: int, status: str | None) -> list[Category]: ...


@dataclass(frozen=True)
class ListCategoriesRequest:
    company_id: int
    status: str | None = "active"


@dataclass(frozen=True)
class ListCategoriesResponse:
    categories: list[Category]


def list_categories(repo: CategoryListRepository, req: ListCategoriesRequest) -> ListCategoriesResponse:
    company_id = _validate_company_id(req.company_id)
    status = _validate_status(req.status)
    categories = repo.list_categories(company_id=company_id, status=status)
    return ListCategoriesResponse(categories=categories)


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_status(status: str | None) -> str | None:
    if status is None:
        return None
    if not isinstance(status, str):
        raise ValidationError("status inválido")
    v = status.strip().lower()
    if v not in ("active", "inactive"):
        raise ValidationError("status inválido")
    return v

