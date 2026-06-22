from dataclasses import dataclass
import math
from typing import Protocol

from gestor_inventory.domain.errors import ValidationError
from gestor_inventory.domain.sat import SatProducto, SatRegimen, SatUnidad


class SatCatalogListRepository(Protocol):
    def count_sat_regimenes(self, *, search: str | None) -> int: ...

    def list_sat_regimenes(self, *, search: str | None, limit: int, offset: int) -> list[SatRegimen]: ...

    def count_sat_unidades(self, *, search: str | None) -> int: ...

    def list_sat_unidades(self, *, search: str | None, limit: int, offset: int) -> list[SatUnidad]: ...

    def count_sat_productos(self, *, search: str | None) -> int: ...

    def list_sat_productos(self, *, search: str | None, limit: int, offset: int) -> list[SatProducto]: ...


@dataclass(frozen=True)
class ListSatCatalogRequest:
    search: str | None = None
    page: int = 1
    per_page: int = 50


@dataclass(frozen=True)
class ListSatCatalogResponse:
    items: list[SatRegimen | SatUnidad | SatProducto]
    total: int
    page: int
    per_page: int
    pages: int


def list_sat_regimenes_use_case(
    repo: SatCatalogListRepository, req: ListSatCatalogRequest
) -> ListSatCatalogResponse:
    page, per_page, search, offset = _validate_request(req)
    total = int(repo.count_sat_regimenes(search=search))
    items = repo.list_sat_regimenes(search=search, limit=per_page, offset=offset)
    return _build_response(items=items, total=total, page=page, per_page=per_page)


def list_sat_unidades_use_case(repo: SatCatalogListRepository, req: ListSatCatalogRequest) -> ListSatCatalogResponse:
    page, per_page, search, offset = _validate_request(req)
    total = int(repo.count_sat_unidades(search=search))
    items = repo.list_sat_unidades(search=search, limit=per_page, offset=offset)
    return _build_response(items=items, total=total, page=page, per_page=per_page)


def list_sat_productos_use_case(repo: SatCatalogListRepository, req: ListSatCatalogRequest) -> ListSatCatalogResponse:
    page, per_page, search, offset = _validate_request(req)
    total = int(repo.count_sat_productos(search=search))
    items = repo.list_sat_productos(search=search, limit=per_page, offset=offset)
    return _build_response(items=items, total=total, page=page, per_page=per_page)


def _validate_request(req: ListSatCatalogRequest) -> tuple[int, int, str | None, int]:
    page = _validate_page(req.page)
    per_page = _validate_per_page(req.per_page)
    search = _normalize_search(req.search)
    offset = (page - 1) * per_page
    return page, per_page, search, offset


def _build_response(
    *, items: list[SatRegimen | SatUnidad | SatProducto], total: int, page: int, per_page: int
) -> ListSatCatalogResponse:
    pages = int(math.ceil(total / per_page)) if per_page > 0 else 0
    return ListSatCatalogResponse(items=items, total=total, page=page, per_page=per_page, pages=pages)


def _validate_page(page: int) -> int:
    if not isinstance(page, int) or page <= 0:
        raise ValidationError("page inválido")
    return page


def _validate_per_page(per_page: int) -> int:
    if not isinstance(per_page, int) or per_page <= 0 or per_page > 100:
        raise ValidationError("per_page inválido")
    return per_page


def _normalize_search(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError("search inválido")
    normalized = value.strip()
    return normalized or None
