from dataclasses import dataclass
import sqlite3
from typing import Protocol

from gestor_inventory.domain.errors import ValidationError
from gestor_inventory.domain.operational import Product


class ProductRepository(Protocol):
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

    def list_products(self, *, company_id: int) -> list[Product]: ...


@dataclass(frozen=True)
class CreateProductRequest:
    company_id: int
    category_id: int | None
    sku: str
    name: str
    description: str | None


@dataclass(frozen=True)
class CreateProductResponse:
    product: Product


@dataclass(frozen=True)
class ListProductsRequest:
    company_id: int


@dataclass(frozen=True)
class ListProductsResponse:
    products: list[Product]


def create_product(repo: ProductRepository, req: CreateProductRequest) -> CreateProductResponse:
    company_id = _validate_company_id(req.company_id)
    category_id = _validate_category_id(req.category_id) if req.category_id is not None else None
    sku = _validate_sku(req.sku)
    name = _validate_name(req.name)
    description = _validate_description(req.description) if req.description is not None else None
    try:
        product = repo.create_product(
            company_id=company_id,
            category_id=category_id,
            sku=sku,
            name=name,
            description=description,
            is_active=True,
        )
    except sqlite3.IntegrityError:
        raise ValidationError("sku ya existe") from None
    return CreateProductResponse(product=product)


def list_products(repo: ProductRepository, req: ListProductsRequest) -> ListProductsResponse:
    company_id = _validate_company_id(req.company_id)
    products = repo.list_products(company_id=company_id)
    return ListProductsResponse(products=products)


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_category_id(category_id: int) -> int:
    if not isinstance(category_id, int) or category_id <= 0:
        raise ValidationError("category_id inválido")
    return category_id


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


def _validate_description(description: str) -> str | None:
    if not isinstance(description, str):
        raise ValidationError("description inválido")
    v = description.strip()
    return v if v else None
