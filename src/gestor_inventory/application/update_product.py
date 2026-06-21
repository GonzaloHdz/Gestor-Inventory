from dataclasses import dataclass
import sqlite3
from typing import Protocol

from gestor_inventory.domain.errors import DuplicateSKUError, InvalidCategoryError, NotFoundError, ValidationError
from gestor_inventory.domain.operational import Product


class ProductUpdateRepository(Protocol):
    def company_is_active(self, *, company_id: int) -> bool: ...

    def get_product_by_id(self, *, company_id: int, product_id: int) -> Product | None: ...

    def get_product_by_sku(self, *, company_id: int, sku: str) -> Product | None: ...

    def get_category_by_id(self, *, company_id: int, category_id: int) -> object | None: ...

    def update_product(
        self,
        *,
        company_id: int,
        product_id: int,
        name: str | None,
        sku: str | None,
        category_id: int | None,
        stock_minimum: int | None,
        status: str | None,
    ) -> Product: ...


@dataclass(frozen=True)
class UpdateProductRequest:
    company_id: int
    product_id: int
    name: str | None = None
    sku: str | None = None
    category_id: int | None = None
    stock_minimum: int | None = None
    status: str | None = None


@dataclass(frozen=True)
class UpdateProductResponse:
    product: Product


def update_product(repo: ProductUpdateRepository, req: UpdateProductRequest) -> UpdateProductResponse:
    company_id = _validate_company_id(req.company_id)
    product_id = _validate_product_id(req.product_id)
    name = _normalize_optional_str(req.name, field="name")
    sku = _normalize_optional_str(req.sku, field="sku")
    category_id = _validate_optional_int_id(req.category_id, field="category_id")
    stock_minimum = _validate_optional_stock_minimum(req.stock_minimum)
    status = _validate_optional_status(req.status)

    if name is None and sku is None and category_id is None and stock_minimum is None and status is None:
        raise ValidationError("no hay campos para actualizar")

    if not repo.company_is_active(company_id=company_id):
        raise NotFoundError("producto no encontrado")

    current = repo.get_product_by_id(company_id=company_id, product_id=product_id)
    if current is None:
        raise NotFoundError("producto no encontrado")

    if sku is not None:
        existing = repo.get_product_by_sku(company_id=company_id, sku=sku)
        if existing is not None and int(existing.id) != int(product_id):
            raise DuplicateSKUError("sku ya existe")

    if category_id is not None and repo.get_category_by_id(company_id=company_id, category_id=category_id) is None:
        raise InvalidCategoryError("category_id no pertenece a la empresa")

    try:
        updated = repo.update_product(
            company_id=company_id,
            product_id=product_id,
            name=name,
            sku=sku,
            category_id=category_id,
            stock_minimum=stock_minimum,
            status=status,
        )
    except sqlite3.IntegrityError as e:
        msg = str(e).lower()
        if "unique constraint failed" in msg and "products.company_id" in msg and "products.sku" in msg:
            raise DuplicateSKUError("sku ya existe") from None
        if "foreign key constraint failed" in msg:
            raise InvalidCategoryError("category_id inválido") from None
        raise

    return UpdateProductResponse(product=updated)


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_product_id(product_id: int) -> int:
    if not isinstance(product_id, int) or product_id <= 0:
        raise ValidationError("product_id inválido")
    return product_id


def _normalize_optional_str(value: str | None, *, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError(f"{field} inválido")
    v = value.strip()
    if not v:
        raise ValidationError(f"{field} inválido")
    return v


def _validate_optional_int_id(value: int | None, *, field: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or value <= 0:
        raise ValidationError(f"{field} inválido")
    return value


def _validate_optional_stock_minimum(value: int | None) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or value < 0:
        raise ValidationError("stock_minimum inválido")
    return value


def _validate_optional_status(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError("status inválido")
    v = value.strip().lower()
    if v not in ("active", "inactive"):
        raise ValidationError("status inválido")
    return v

