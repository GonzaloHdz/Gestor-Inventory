from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.company_setting import CompanySetting
from gestor_inventory.domain.errors import ValidationError


class CompanySettingsRepository(Protocol):
    def get_company_settings(self, *, company_id: int) -> list[CompanySetting]: ...


@dataclass(frozen=True)
class GetCompanySettingsRequest:
    company_id: int


@dataclass(frozen=True)
class GetCompanySettingsResponse:
    settings: list[CompanySetting]


def get_company_settings(repo: CompanySettingsRepository, req: GetCompanySettingsRequest) -> GetCompanySettingsResponse:
    company_id = _validate_company_id(req.company_id)
    settings = repo.get_company_settings(company_id=company_id)
    return GetCompanySettingsResponse(settings=settings)


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id
