from dataclasses import dataclass
import sqlite3
from typing import Protocol

from gestor_inventory.domain.errors import CrossTenantReferenceError, DuplicateSKUError, InvalidCategoryError, ValidationError
from gestor_inventory.domain.operational import Product


class ProductRepository(Protocol):
    def company_is_active(self, *, company_id: int) -> bool: ...

    def get_category_by_id(self, *, company_id: int, category_id: int) -> object | None: ...

    def create_product(
        self,
        *,
        company_id: int,
        category_id: int,
        sku: str,
        name: str,
        description: str | None,
        stock_minimum: int,
        status: str,
    ) -> Product: ...

    def get_product_by_sku(self, *, company_id: int, sku: str) -> Product | None: ...


@dataclass(frozen=True)
class CreateProductRequest:
    company_id: int
    sku: str
    name: str
    category_id: int
    description: str | None = None
    stock_minimum: int = 0
    status: str = "active"


@dataclass(frozen=True)
class CreateProductResponse:
    product: Product


def create_product(repo: ProductRepository, req: CreateProductRequest) -> CreateProductResponse:
    company_id = _validate_company_id(req.company_id)
    sku = _validate_sku(req.sku)
    name = _validate_name(req.name)
    description = _normalize_optional(req.description)
    category_id = _validate_category_id(req.category_id)
    stock_minimum = _validate_stock_minimum(req.stock_minimum)
    status = _validate_status(req.status)

    if not repo.company_is_active(company_id=company_id):
        raise CrossTenantReferenceError("empresa inválida")

    if repo.get_category_by_id(company_id=company_id, category_id=category_id) is None:
        raise InvalidCategoryError("category_id no pertenece a la empresa")

    if repo.get_product_by_sku(company_id=company_id, sku=sku) is not None:
        raise DuplicateSKUError("sku ya existe")

    try:
        product = repo.create_product(
            company_id=company_id,
            category_id=category_id,
            sku=sku,
            name=name,
            description=description,
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
    return CreateProductResponse(product=product)


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_sku(sku: str) -> str:
    if not isinstance(sku, str):
        raise ValidationError("sku inválido")
    v = sku.strip()
    if not v:
        raise ValidationError("sku inválido")
    return v


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
        raise ValidationError("description inválido")
    v = value.strip()
    return v or None


def _validate_category_id(value: int) -> int:
    if not isinstance(value, int) or value <= 0:
        raise ValidationError("category_id inválido")
    return value


def _validate_stock_minimum(value: int) -> int:
    if not isinstance(value, int) or value < 0:
        raise ValidationError("stock_minimum inválido")
    return value


def _validate_status(value: str) -> str:
    if not isinstance(value, str):
        raise ValidationError("status inválido")
    v = value.strip().lower()
    if v not in ("active", "inactive"):
        raise ValidationError("status inválido")
    return v
