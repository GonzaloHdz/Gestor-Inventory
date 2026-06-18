from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.errors import CrossTenantReferenceError, ValidationError
from gestor_inventory.domain.operational import Product


class ProductRepository(Protocol):
    def company_is_active(self, *, company_id: int) -> bool: ...

    def get_category_by_id(self, *, company_id: int, category_id: int) -> object | None: ...

    def create_product(
        self,
        *,
        company_id: int,
        category_id: int | None,
        sku: str,
        name: str,
        description: str | None,
        is_active: bool,
    ) -> Product: ...


@dataclass(frozen=True)
class CreateProductRequest:
    company_id: int
    sku: str
    name: str
    category_id: int | None = None
    description: str | None = None


@dataclass(frozen=True)
class CreateProductResponse:
    product: Product


def create_product(repo: ProductRepository, req: CreateProductRequest) -> CreateProductResponse:
    company_id = _validate_company_id(req.company_id)
    sku = _validate_sku(req.sku)
    name = _validate_name(req.name)
    description = _normalize_optional(req.description)
    category_id = _validate_optional_id(req.category_id, field="category_id")

    if not repo.company_is_active(company_id=company_id):
        raise CrossTenantReferenceError("empresa inválida")

    if category_id is not None and repo.get_category_by_id(company_id=company_id, category_id=category_id) is None:
        raise CrossTenantReferenceError("category_id no pertenece a la empresa")

    product = repo.create_product(
        company_id=company_id,
        category_id=category_id,
        sku=sku,
        name=name,
        description=description,
        is_active=True,
    )
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


def _validate_optional_id(value: int | None, *, field: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or value <= 0:
        raise ValidationError(f"{field} inválido")
    return value
