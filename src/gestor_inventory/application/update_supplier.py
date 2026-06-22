from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.errors import NotFoundError, ValidationError
from gestor_inventory.domain.operational import Supplier


class SupplierUpdateRepository(Protocol):
    def supplier_belongs_to_company(self, *, company_id: int, supplier_id: int) -> bool: ...

    def update_supplier(
        self,
        *,
        company_id: int,
        supplier_id: int,
        name: str | None,
        contact_email: str | None,
        phone: str | None,
        status: str | None,
    ) -> Supplier: ...


@dataclass(frozen=True)
class UpdateSupplierRequest:
    company_id: int
    supplier_id: int
    name: str | None = None
    contact_email: str | None = None
    phone: str | None = None
    status: str | None = None


@dataclass(frozen=True)
class UpdateSupplierResponse:
    supplier: Supplier


def update_supplier(repo: SupplierUpdateRepository, req: UpdateSupplierRequest) -> UpdateSupplierResponse:
    company_id = _validate_company_id(req.company_id)
    supplier_id = _validate_supplier_id(req.supplier_id)
    name = _normalize_optional(req.name, field="name")
    contact_email = _normalize_optional(req.contact_email, field="contact_email")
    phone = _normalize_optional(req.phone, field="phone")
    status = _validate_status(req.status)

    if name is None and contact_email is None and phone is None and status is None:
        raise ValidationError("no hay campos para actualizar")

    if not repo.supplier_belongs_to_company(company_id=company_id, supplier_id=supplier_id):
        raise NotFoundError("proveedor no encontrado")

    updated = repo.update_supplier(
        company_id=company_id,
        supplier_id=supplier_id,
        name=name,
        contact_email=contact_email,
        phone=phone,
        status=status,
    )
    return UpdateSupplierResponse(supplier=updated)


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_supplier_id(supplier_id: int) -> int:
    if not isinstance(supplier_id, int) or supplier_id <= 0:
        raise ValidationError("supplier_id inválido")
    return supplier_id


def _normalize_optional(value: str | None, *, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError(f"{field} inválido")
    v = value.strip()
    return v or None


def _validate_status(status: str | None) -> str | None:
    if status is None:
        return None
    if not isinstance(status, str):
        raise ValidationError("status inválido")
    v = status.strip().lower()
    if v not in ("active", "inactive"):
        raise ValidationError("status inválido")
    return v
