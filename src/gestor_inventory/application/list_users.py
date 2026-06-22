from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.errors import ValidationError


@dataclass(frozen=True)
class UserListItem:
    id: int
    company_id: int
    email: str
    is_active: bool
    verified: bool
    roles: list[str]


class UserListRepository(Protocol):
    def count_users_by_company(self, *, company_id: int) -> int: ...

    def list_users_by_company(self, *, company_id: int, limit: int, offset: int) -> list[UserListItem]: ...


@dataclass(frozen=True)
class ListUsersRequest:
    company_id: int
    page: int = 1
    per_page: int = 20


@dataclass(frozen=True)
class ListUsersResponse:
    users: list[UserListItem]
    total: int
    page: int
    per_page: int
    pages: int


def list_users(repo: UserListRepository, req: ListUsersRequest) -> ListUsersResponse:
    company_id = _validate_company_id(req.company_id)
    page = _validate_page(req.page)
    per_page = _validate_per_page(req.per_page)
    offset = (page - 1) * per_page

    total = int(repo.count_users_by_company(company_id=company_id))
    pages = (total + per_page - 1) // per_page
    if pages <= 0:
        pages = 1

    users = repo.list_users_by_company(company_id=company_id, limit=per_page, offset=offset)
    return ListUsersResponse(users=users, total=total, page=page, per_page=per_page, pages=pages)


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_page(page: int) -> int:
    if not isinstance(page, int) or page <= 0:
        raise ValidationError("page inválido")
    return page


def _validate_per_page(per_page: int) -> int:
    if not isinstance(per_page, int) or per_page <= 0 or per_page > 100:
        raise ValidationError("per_page inválido")
    return per_page
