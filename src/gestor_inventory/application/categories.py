from dataclasses import dataclass
import sqlite3
from typing import Protocol

from gestor_inventory.domain.errors import NotFoundError, ValidationError
from gestor_inventory.domain.operational import Category


class CategoryRepository(Protocol):
    def create_category(self, *, company_id: int, name: str, is_active: bool) -> Category: ...

    def get_category_by_id(self, *, company_id: int, category_id: int) -> Category | None: ...


@dataclass(frozen=True)
class CreateCategoryRequest:
    company_id: int
    name: str


@dataclass(frozen=True)
class CreateCategoryResponse:
    category: Category


@dataclass(frozen=True)
class GetCategoryRequest:
    company_id: int
    category_id: int


@dataclass(frozen=True)
class GetCategoryResponse:
    category: Category


def create_category(repo: CategoryRepository, req: CreateCategoryRequest) -> CreateCategoryResponse:
    company_id = _validate_company_id(req.company_id)
    name = _validate_name(req.name)
    try:
        category = repo.create_category(company_id=company_id, name=name, is_active=True)
    except sqlite3.IntegrityError:
        raise ValidationError("categoría ya existe") from None
    return CreateCategoryResponse(category=category)


def get_category(repo: CategoryRepository, req: GetCategoryRequest) -> GetCategoryResponse:
    company_id = _validate_company_id(req.company_id)
    category_id = _validate_category_id(req.category_id)
    category = repo.get_category_by_id(company_id=company_id, category_id=category_id)
    if category is None:
        raise NotFoundError("categoría no encontrada")
    return GetCategoryResponse(category=category)


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_category_id(category_id: int) -> int:
    if not isinstance(category_id, int) or category_id <= 0:
        raise ValidationError("category_id inválido")
    return category_id


def _validate_name(name: str) -> str:
    if not isinstance(name, str):
        raise ValidationError("name inválido")
    v = name.strip()
    if not v:
        raise ValidationError("name inválido")
    return v
