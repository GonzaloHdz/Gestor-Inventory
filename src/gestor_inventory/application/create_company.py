from dataclasses import dataclass
import time
from typing import Protocol

from gestor_inventory.domain.company import Company
from gestor_inventory.domain.errors import CompanyNameAlreadyExistsError, ValidationError


class CompanyRepository(Protocol):
    def company_name_exists(self, *, name: str) -> bool: ...

    def create_company(self, *, name: str, currency: str, timezone: str, created_at: int) -> Company: ...


@dataclass(frozen=True)
class CreateCompanyRequest:
    name: str
    currency: str
    timezone: str


@dataclass(frozen=True)
class CreateCompanyResponse:
    company: Company


def create_company(repo: CompanyRepository, req: CreateCompanyRequest, *, now: int | None = None) -> CreateCompanyResponse:
    name = _validate_name(req.name)
    currency = _validate_currency(req.currency)
    timezone = _validate_timezone(req.timezone)
    now_v = int(time.time()) if now is None else int(now)

    if repo.company_name_exists(name=name):
        raise CompanyNameAlreadyExistsError()

    company = repo.create_company(name=name, currency=currency, timezone=timezone, created_at=now_v)
    return CreateCompanyResponse(company=company)


def _validate_name(name: str) -> str:
    if not isinstance(name, str):
        raise ValidationError("name inválido")
    v = name.strip()
    if not v:
        raise ValidationError("name inválido")
    return v


def _validate_currency(currency: str) -> str:
    if not isinstance(currency, str):
        raise ValidationError("currency inválido")
    v = currency.strip().upper()
    if not v or len(v) > 8:
        raise ValidationError("currency inválido")
    return v


def _validate_timezone(timezone: str) -> str:
    if not isinstance(timezone, str):
        raise ValidationError("timezone inválido")
    v = timezone.strip()
    if not v:
        raise ValidationError("timezone inválido")
    return v
