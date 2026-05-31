from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.errors import NotFoundError, ValidationError
from gestor_inventory.domain.operational import InventoryItem, InventoryMovement


class InventoryRepository(Protocol):
    def branch_belongs_to_company(self, *, company_id: int, branch_id: int) -> bool: ...

    def list_inventory_items(self, *, company_id: int, branch_id: int) -> list[InventoryItem]: ...

    def list_inventory_movements(self, *, company_id: int, branch_id: int, limit: int) -> list[InventoryMovement]: ...


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
