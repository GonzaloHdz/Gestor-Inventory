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
    description: str | None
    status: str
    is_active: bool

    def __post_init__(self) -> None:
        if not isinstance(self.company_id, int) or self.company_id <= 0:
            raise ValueError("company_id inválido")
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("name inválido")
        if self.description is not None and (not isinstance(self.description, str) or not self.description.strip()):
            raise ValueError("description inválido")
        if not isinstance(self.status, str) or self.status not in ("active", "inactive"):
            raise ValueError("status inválido")
        if bool(self.is_active) != (self.status == "active"):
            raise ValueError("inconsistencia status/is_active")


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


@dataclass(frozen=True)
class Supplier:
    company_id: int
    id: int
    name: str
    document_id: str | None
    contact_email: str | None
    phone: str | None
    status: str
    created_at: int
    updated_at: int

    def __post_init__(self) -> None:
        if not isinstance(self.company_id, int) or self.company_id <= 0:
            raise ValueError("company_id inválido")
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("name inválido")
        if self.document_id is not None and (not isinstance(self.document_id, str) or not self.document_id.strip()):
            raise ValueError("document_id inválido")
        if self.contact_email is not None and (
            not isinstance(self.contact_email, str) or not self.contact_email.strip()
        ):
            raise ValueError("contact_email inválido")
        if self.phone is not None and (not isinstance(self.phone, str) or not self.phone.strip()):
            raise ValueError("phone inválido")
        if not isinstance(self.status, str) or self.status not in ("active", "inactive"):
            raise ValueError("status inválido")
