from dataclasses import dataclass
import math
from typing import Protocol

from gestor_inventory.domain.errors import ValidationError
from gestor_inventory.domain.operational import Product


class ProductListRepository(Protocol):
    def count_products(self, *, company_id: int, category_id: int | None, status: str | None) -> int: ...

    def list_products(
        self,
        *,
        company_id: int,
        category_id: int | None,
        status: str | None,
        limit: int,
        offset: int,
    ) -> list[Product]: ...


@dataclass(frozen=True)
class ListProductsRequest:
    company_id: int
    category_id: int | None = None
    status: str | None = "active"
    page: int = 1
    per_page: int = 50


@dataclass(frozen=True)
class ListProductsResponse:
    products: list[Product]
    total: int
    page: int
    per_page: int
    pages: int


def list_products(repo: ProductListRepository, req: ListProductsRequest) -> ListProductsResponse:
    company_id = _validate_company_id(req.company_id)
    category_id = _validate_category_id(req.category_id)
    status = _validate_status(req.status)
    page = _validate_page(req.page)
    per_page = _validate_per_page(req.per_page)

    offset = (page - 1) * per_page
    total = int(repo.count_products(company_id=company_id, category_id=category_id, status=status))
    products = repo.list_products(
        company_id=company_id,
        category_id=category_id,
        status=status,
        limit=per_page,
        offset=offset,
    )
    pages = int(math.ceil(total / per_page)) if per_page > 0 else 0
    return ListProductsResponse(products=products, total=total, page=page, per_page=per_page, pages=pages)


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_category_id(category_id: int | None) -> int | None:
    if category_id is None:
        return None
    if not isinstance(category_id, int) or category_id <= 0:
        raise ValidationError("category_id inválido")
    return category_id


def _validate_status(status: str | None) -> str | None:
    if status is None:
        return None
    if not isinstance(status, str):
        raise ValidationError("status inválido")
    v = status.strip().lower()
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

