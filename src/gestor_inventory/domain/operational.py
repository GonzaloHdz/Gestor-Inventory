from dataclasses import dataclass


@dataclass(frozen=True)
class Branch:
    company_id: int
    id: int
    name: str
    address: str | None
    city: str | None
    country: str | None
    status: str
    is_active: bool

    def __post_init__(self) -> None:
        if not isinstance(self.company_id, int) or self.company_id <= 0:
            raise ValueError("company_id inválido")
        if self.city is not None and (not isinstance(self.city, str) or not self.city.strip()):
            raise ValueError("city inválido")
        if self.country is not None and (not isinstance(self.country, str) or not self.country.strip()):
            raise ValueError("country inválido")
        if not isinstance(self.status, str) or self.status not in ("active", "inactive"):
            raise ValueError("status inválido")


@dataclass(frozen=True)
class Category:
    company_id: int
    id: int
    name: str
    is_active: bool

    def __post_init__(self) -> None:
        if not isinstance(self.company_id, int) or self.company_id <= 0:
            raise ValueError("company_id inválido")


@dataclass(frozen=True)
class Product:
    company_id: int
    id: int
    category_id: int | None
    sku: str
    name: str
    description: str | None
    is_active: bool

    def __post_init__(self) -> None:
        if not isinstance(self.company_id, int) or self.company_id <= 0:
            raise ValueError("company_id inválido")


@dataclass(frozen=True)
class InventoryItem:
    company_id: int
    branch_id: int
    product_id: int
    quantity: int
    min_quantity: int
    updated_at: int

    def __post_init__(self) -> None:
        if not isinstance(self.company_id, int) or self.company_id <= 0:
            raise ValueError("company_id inválido")
        if not isinstance(self.branch_id, int) or self.branch_id <= 0:
            raise ValueError("branch_id inválido")


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

    def __post_init__(self) -> None:
        if not isinstance(self.company_id, int) or self.company_id <= 0:
            raise ValueError("company_id inválido")
        if not isinstance(self.branch_id, int) or self.branch_id <= 0:
            raise ValueError("branch_id inválido")
