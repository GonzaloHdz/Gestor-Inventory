from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.company import Company
from gestor_inventory.domain.errors import ValidationError


class VerifyCompanyRepository(Protocol):
    def find_company_by_verification_token(self, *, token: str) -> Company | None: ...
    def verify_company_in_db(self, *, company_id: int) -> None: ...


@dataclass(frozen=True)
class VerifyCompanyRequest:
    token: str


def verify_company(repo: VerifyCompanyRepository, req: VerifyCompanyRequest) -> None:
    token = req.token.strip() if req.token else ""
    if not token:
        raise ValidationError("Token inválido o empresa no encontrada.")

    company = repo.find_company_by_verification_token(token=token)
    if company is None:
        raise ValidationError("Token inválido o empresa no encontrada.")

    repo.verify_company_in_db(company_id=company.id)
