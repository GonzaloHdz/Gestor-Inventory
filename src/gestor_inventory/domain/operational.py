from dataclasses import dataclass


@dataclass(frozen=True)
class Branch:
    company_id: int
    id: int
    name: str
    address: str | None
    is_active: bool


@dataclass(frozen=True)
class Category:
    company_id: int
    id: int
    name: str
    is_active: bool


@dataclass(frozen=True)
class Product:
    company_id: int
    id: int
    category_id: int | None
    sku: str
    name: str
    description: str | None
    is_active: bool


@dataclass(frozen=True)
class InventoryItem:
    company_id: int
    branch_id: int
    product_id: int
    quantity: int
    min_quantity: int
    updated_at: int


@dataclass(frozen=True)
class InventoryMovement:
    company_id: int
    id: int
    branch_id: int
    product_id: int
    user_id: int
    movement_type: str
    quantity: int
    reference: str | None
    created_at: int
