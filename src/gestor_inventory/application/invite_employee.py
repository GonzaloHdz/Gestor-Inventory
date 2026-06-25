from dataclasses import dataclass
from typing import Protocol
import uuid

from gestor_inventory.domain.company import Company
from gestor_inventory.domain.errors import EmailAlreadyExistsError, ValidationError
from gestor_inventory.domain.user import User


class InviteEmployeeRepository(Protocol):
    def email_exists(self, *, company_id: int, email: str) -> bool: ...
    def create_user_with_role(
        self,
        *,
        company_id: int,
        email: str,
        password_hash: str,
        role_id: int,
        verification_token: str | None = None,
    ) -> tuple[User, int]: ...
    def get_company_by_id(self, *, company_id: int) -> Company | None: ...


@dataclass(frozen=True)
class InviteEmployeeRequest:
    admin_company_id: int
    email: str
    role: str | None = "employee"


@dataclass(frozen=True)
class InviteEmployeeResponse:
    user: User
    company_name: str
    verification_token: str
    verification_url: str


ROLE_MAPPING = {
    "employee": 10,
    "almacenista": 10,
    "supervisor": 11,
    "admin": 12,
    "administrador": 12,
    "superadmin": 13,
    "superadministrador": 13,
}


def invite_employee(
    repo: InviteEmployeeRepository,
    req: InviteEmployeeRequest,
    *,
    base_url: str = "https://example.com",
) -> InviteEmployeeResponse:
    email = _normalize_email(req.email)
    role_str = (req.role or "employee").strip().lower()
    role_id = ROLE_MAPPING.get(role_str)
    if role_id is None:
        raise ValidationError("Rol inválido.")

    if repo.email_exists(company_id=req.admin_company_id, email=email):
        raise EmailAlreadyExistsError()

    company = repo.get_company_by_id(company_id=req.admin_company_id)
    if company is None:
        raise ValidationError("Empresa no encontrada.")

    token = str(uuid.uuid4())
    user, _ = repo.create_user_with_role(
        company_id=req.admin_company_id,
        email=email,
        password_hash="",
        role_id=role_id,
        verification_token=token,
    )

    verification_url = f"{base_url.rstrip('/')}/set-password?token={token}"
    return InviteEmployeeResponse(
        user=user,
        company_name=company.name,
        verification_token=token,
        verification_url=verification_url,
    )


def _normalize_email(email: str) -> str:
    if not isinstance(email, str):
        raise ValidationError("email inválido")
    normalized = email.strip().lower()
    if not normalized or "@" not in normalized:
        raise ValidationError("email inválido")
    return normalized
