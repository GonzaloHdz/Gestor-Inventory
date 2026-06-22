from dataclasses import dataclass
import math
from typing import Protocol

from gestor_inventory.domain.errors import ValidationError
from gestor_inventory.domain.operational import Supplier


class SupplierListRepository(Protocol):
    def count_suppliers(
        self,
        *,
        company_id: int,
        name: str | None,
        document_id: str | None,
        status: str | None,
    ) -> int: ...

    def list_suppliers(
        self,
        *,
        company_id: int,
        name: str | None,
        document_id: str | None,
        status: str | None,
        limit: int,
        offset: int,
    ) -> list[Supplier]: ...


@dataclass(frozen=True)
class ListSuppliersRequest:
    company_id: int
    name: str | None = None
    document_id: str | None = None
    status: str | None = "active"
    page: int = 1
    per_page: int = 50


@dataclass(frozen=True)
class ListSuppliersResponse:
    suppliers: list[Supplier]
    total: int
    page: int
    per_page: int
    pages: int


def list_suppliers(repo: SupplierListRepository, req: ListSuppliersRequest) -> ListSuppliersResponse:
    company_id = _validate_company_id(req.company_id)
    name = _normalize_optional(req.name)
    document_id = _normalize_optional(req.document_id)
    status = _validate_status(req.status)
    page = _validate_page(req.page)
    per_page = _validate_per_page(req.per_page)

    offset = (page - 1) * per_page
    total = int(
        repo.count_suppliers(company_id=company_id, name=name, document_id=document_id, status=status)
    )
    suppliers = repo.list_suppliers(
        company_id=company_id,
        name=name,
        document_id=document_id,
        status=status,
        limit=per_page,
        offset=offset,
    )
    pages = int(math.ceil(total / per_page)) if per_page > 0 else 0
    return ListSuppliersResponse(suppliers=suppliers, total=total, page=page, per_page=per_page, pages=pages)


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _normalize_optional(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError("valor inválido")
    v = value.strip()
    return v or None


def _validate_status(status: str | None) -> str | None:
    if status is None:
        return None
    if not isinstance(status, str):
        raise ValidationError("status inválido")
    v = status.strip().lower()
    if v in ("", "all", "todas", "any"):
        return None
    if v not in ("active", "inactive"):
        raise ValidationError("status inválido")
    return v


def _validate_page(page: int) -> int:
    if not isinstance(page, int) or page <= 0:
        raise ValidationError("page inválido")
    return page


def _validate_per_page(per_page: int) -> int:
    if not isinstance(per_page, int) or per_page <= 0 or per_page > 200:
        raise ValidationError("per_page inválido")
    return per_page
