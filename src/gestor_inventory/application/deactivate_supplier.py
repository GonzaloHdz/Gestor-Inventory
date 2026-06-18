from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.errors import NotFoundError, ValidationError


class SupplierDeactivateRepository(Protocol):
    def supplier_belongs_to_company(self, *, company_id: int, supplier_id: int) -> bool: ...

    def deactivate_supplier(self, *, company_id: int, supplier_id: int) -> str: ...


@dataclass(frozen=True)
class DeactivateSupplierRequest:
    company_id: int
    supplier_id: int


@dataclass(frozen=True)
class DeactivateSupplierResponse:
    changed: bool


def deactivate_supplier(
    repo: SupplierDeactivateRepository, req: DeactivateSupplierRequest
) -> DeactivateSupplierResponse:
    company_id = _validate_company_id(req.company_id)
    supplier_id = _validate_supplier_id(req.supplier_id)

    if not repo.supplier_belongs_to_company(company_id=company_id, supplier_id=supplier_id):
        raise NotFoundError("proveedor no encontrado")

    status = repo.deactivate_supplier(company_id=company_id, supplier_id=supplier_id)
    if status == "already_inactive":
        return DeactivateSupplierResponse(changed=False)
    if status == "changed":
        return DeactivateSupplierResponse(changed=True)
    if status == "not_found":
        raise NotFoundError("proveedor no encontrado")
    raise ValidationError("operación inválida")


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_supplier_id(supplier_id: int) -> int:
    if not isinstance(supplier_id, int) or supplier_id <= 0:
        raise ValidationError("supplier_id inválido")
    return supplier_id
