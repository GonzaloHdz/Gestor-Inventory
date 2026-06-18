from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.company import Company
from gestor_inventory.domain.errors import ValidationError


class CompanyListRepository(Protocol):
    def count_active_companies(self) -> int: ...

    def list_active_companies(self, *, limit: int, offset: int) -> list[Company]: ...


@dataclass(frozen=True)
class ListCompaniesRequest:
    page: int = 1
    per_page: int = 10


@dataclass(frozen=True)
class ListCompaniesResponse:
    companies: list[Company]
    total: int
    page: int
    per_page: int
    pages: int


def list_companies(repo: CompanyListRepository, req: ListCompaniesRequest) -> ListCompaniesResponse:
    page = _validate_page(req.page)
    per_page = _validate_per_page(req.per_page)
    offset = (page - 1) * per_page

    total = int(repo.count_active_companies())
    pages = (total + per_page - 1) // per_page
    if pages <= 0:
        pages = 1

    companies = repo.list_active_companies(limit=per_page, offset=offset)
    return ListCompaniesResponse(companies=companies, total=total, page=page, per_page=per_page, pages=pages)


def _validate_page(page: int) -> int:
    if not isinstance(page, int) or page <= 0:
        raise ValidationError("page inválido")
    return page


def _validate_per_page(per_page: int) -> int:
    if not isinstance(per_page, int) or per_page <= 0 or per_page > 100:
        raise ValidationError("per_page inválido")
    return per_page
