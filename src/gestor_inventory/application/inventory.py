from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.errors import NotFoundError, ValidationError
from gestor_inventory.domain.operational import InventoryItem, InventoryMovement


class InventoryRepository(Protocol):
    def branch_belongs_to_company(self, *, company_id: int, branch_id: int) -> bool: ...

    def product_belongs_to_company(self, *, company_id: int, product_id: int) -> bool: ...

    def user_belongs_to_company(self, *, company_id: int, user_id: int) -> bool: ...

    def list_inventory_items(self, *, company_id: int, branch_id: int) -> list[InventoryItem]: ...

    def list_inventory_movements(self, *, company_id: int, branch_id: int, limit: int) -> list[InventoryMovement]: ...

    def register_inventory_movement(
        self,
        *,
        company_id: int,
        branch_id: int,
        product_id: int,
        user_id: int,
        movement_type: str,
        quantity: int,
        reference: str | None,
    ) -> tuple[InventoryItem, InventoryMovement]: ...


@dataclass(frozen=True)
class ListInventoryRequest:
    company_id: int
    branch_id: int


@dataclass(frozen=True)
class ListInventoryResponse:
    items: list[InventoryItem]


@dataclass(frozen=True)
class ListInventoryMovementsRequest:
    company_id: int
    branch_id: int
    limit: int = 50


@dataclass(frozen=True)
class ListInventoryMovementsResponse:
    movements: list[InventoryMovement]


@dataclass(frozen=True)
class RegisterInventoryMovementRequest:
    company_id: int
    branch_id: int
    product_id: int
    user_id: int
    movement_type: str
    quantity: int
    reference: str | None = None


@dataclass(frozen=True)
class RegisterInventoryMovementResponse:
    item: InventoryItem
    movement: InventoryMovement


def list_inventory(repo: InventoryRepository, req: ListInventoryRequest) -> ListInventoryResponse:
    company_id = _validate_company_id(req.company_id)
    branch_id = _validate_branch_id(req.branch_id)
    if not repo.branch_belongs_to_company(company_id=company_id, branch_id=branch_id):
        raise NotFoundError("sucursal no encontrada")
    items = repo.list_inventory_items(company_id=company_id, branch_id=branch_id)
    return ListInventoryResponse(items=items)


def list_inventory_movements(
    repo: InventoryRepository, req: ListInventoryMovementsRequest
) -> ListInventoryMovementsResponse:
    company_id = _validate_company_id(req.company_id)
    branch_id = _validate_branch_id(req.branch_id)
    limit = _validate_limit(req.limit)
    if not repo.branch_belongs_to_company(company_id=company_id, branch_id=branch_id):
        raise NotFoundError("sucursal no encontrada")
    movements = repo.list_inventory_movements(company_id=company_id, branch_id=branch_id, limit=limit)
    return ListInventoryMovementsResponse(movements=movements)


def register_inventory_movement(
    repo: InventoryRepository, req: RegisterInventoryMovementRequest
) -> RegisterInventoryMovementResponse:
    company_id = _validate_company_id(req.company_id)
    branch_id = _validate_branch_id(req.branch_id)
    product_id = _validate_product_id(req.product_id)
    user_id = _validate_user_id(req.user_id)
    movement_type = _validate_movement_type(req.movement_type)
    quantity = _validate_quantity(req.quantity)
    reference = _validate_reference(req.reference) if req.reference is not None else None

    if not repo.branch_belongs_to_company(company_id=company_id, branch_id=branch_id):
        raise NotFoundError("sucursal no encontrada")
    if not repo.product_belongs_to_company(company_id=company_id, product_id=product_id):
        raise NotFoundError("producto no encontrado")
    if not repo.user_belongs_to_company(company_id=company_id, user_id=user_id):
        raise NotFoundError("usuario no encontrado")

    item, movement = repo.register_inventory_movement(
        company_id=company_id,
        branch_id=branch_id,
        product_id=product_id,
        user_id=user_id,
        movement_type=movement_type,
        quantity=quantity,
        reference=reference,
    )
    return RegisterInventoryMovementResponse(item=item, movement=movement)


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_branch_id(branch_id: int) -> int:
    if not isinstance(branch_id, int) or branch_id <= 0:
        raise ValidationError("branch_id inválido")
    return branch_id


def _validate_limit(limit: int) -> int:
    if not isinstance(limit, int) or limit <= 0 or limit > 500:
        raise ValidationError("limit inválido")
    return limit


def _validate_product_id(product_id: int) -> int:
    if not isinstance(product_id, int) or product_id <= 0:
        raise ValidationError("product_id inválido")
    return product_id


def _validate_user_id(user_id: int) -> int:
    if not isinstance(user_id, int) or user_id <= 0:
        raise ValidationError("user_id inválido")
    return user_id


def _validate_quantity(quantity: int) -> int:
    if not isinstance(quantity, int) or quantity <= 0:
        raise ValidationError("quantity inválido")
    return quantity


def _validate_movement_type(movement_type: str) -> str:
    if not isinstance(movement_type, str):
        raise ValidationError("movement_type inválido")
    normalized = movement_type.strip().lower()
    if normalized not in {"entrada", "salida"}:
        raise ValidationError("movement_type inválido")
    return normalized


def _validate_reference(reference: str) -> str | None:
    if not isinstance(reference, str):
        raise ValidationError("reference inválido")
    normalized = reference.strip()
    return normalized if normalized else None
