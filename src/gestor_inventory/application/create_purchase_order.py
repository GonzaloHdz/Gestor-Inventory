from dataclasses import dataclass
import time
from typing import Protocol

from gestor_inventory.domain.errors import InvalidSupplierError, SupplierNotFoundError, ValidationError
from gestor_inventory.domain.purchases import PurchaseOrder


class PurchaseOrderRepository(Protocol):
    def supplier_exists(self, *, supplier_id: int) -> bool: ...

    def supplier_belongs_to_company(self, *, company_id: int, supplier_id: int) -> bool: ...

    def supplier_is_active(self, *, company_id: int, supplier_id: int) -> bool: ...

    def create_purchase_order(
        self,
        *,
        company_id: int,
        supplier_id: int,
        status: str,
        created_at: int,
        updated_at: int,
    ) -> PurchaseOrder: ...


@dataclass(frozen=True)
class CreatePurchaseOrderRequest:
    company_id: int
    supplier_id: int


@dataclass(frozen=True)
class CreatePurchaseOrderResponse:
    purchase_order: PurchaseOrder


def create_purchase_order(
    repo: PurchaseOrderRepository,
    req: CreatePurchaseOrderRequest,
    *,
    now: int | None = None,
) -> CreatePurchaseOrderResponse:
    company_id = _validate_company_id(req.company_id)
    supplier_id = _validate_supplier_id(req.supplier_id)
    now_v = int(time.time()) if now is None else int(now)

    if not repo.supplier_exists(supplier_id=supplier_id):
        raise SupplierNotFoundError("proveedor no encontrado")
    if not repo.supplier_belongs_to_company(company_id=company_id, supplier_id=supplier_id):
        raise InvalidSupplierError("proveedor inválido")
    if not repo.supplier_is_active(company_id=company_id, supplier_id=supplier_id):
        raise InvalidSupplierError("proveedor inactivo")

    po = repo.create_purchase_order(
        company_id=company_id,
        supplier_id=supplier_id,
        status="created",
        created_at=now_v,
        updated_at=now_v,
    )
    return CreatePurchaseOrderResponse(purchase_order=po)


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_supplier_id(supplier_id: int) -> int:
    if not isinstance(supplier_id, int) or supplier_id <= 0:
        raise InvalidSupplierError("supplier_id inválido")
    return supplier_id
