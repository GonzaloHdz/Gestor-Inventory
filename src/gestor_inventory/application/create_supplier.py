from dataclasses import dataclass
import sqlite3
import time
from typing import Protocol

from gestor_inventory.domain.errors import CrossTenantReferenceError, ValidationError
from gestor_inventory.domain.operational import Supplier


class SupplierRepository(Protocol):
    def company_is_active(self, *, company_id: int) -> bool: ...

    def create_supplier(
        self,
        *,
        company_id: int,
        name: str,
        document_id: str | None,
        contact_email: str | None,
        phone: str | None,
        status: str,
        created_at: int,
        updated_at: int,
    ) -> Supplier: ...


@dataclass(frozen=True)
class CreateSupplierRequest:
    company_id: int
    name: str
    document_id: str | None = None
    contact_email: str | None = None
    phone: str | None = None


@dataclass(frozen=True)
class CreateSupplierResponse:
    supplier: Supplier


def create_supplier(
    repo: SupplierRepository,
    req: CreateSupplierRequest,
    *,
    now: int | None = None,
) -> CreateSupplierResponse:
    company_id = _validate_company_id(req.company_id)
    name = _validate_name(req.name)
    document_id = _normalize_optional(req.document_id)
    contact_email = _normalize_optional(req.contact_email)
    phone = _normalize_optional(req.phone)
    now_v = int(time.time()) if now is None else int(now)

    if not repo.company_is_active(company_id=company_id):
        raise CrossTenantReferenceError("empresa inválida")

    try:
        supplier = repo.create_supplier(
            company_id=company_id,
            name=name,
            document_id=document_id,
            contact_email=contact_email,
            phone=phone,
            status="active",
            created_at=now_v,
            updated_at=now_v,
        )
    except sqlite3.IntegrityError:
        raise ValidationError("proveedor ya existe") from None

    return CreateSupplierResponse(supplier=supplier)


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


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
        raise ValidationError("valor inválido")
    v = value.strip()
    return v or None
