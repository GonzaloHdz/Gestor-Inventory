from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.errors import ValidationError
from gestor_inventory.domain.user import User
from gestor_inventory.security.password_hash import hash_password
from gestor_inventory.security.password_policy import validate_password_strength


class SetPasswordRepository(Protocol):
    def find_user_by_verification_token(self, *, token: str) -> User | None: ...
    def set_invited_employee_password(self, *, company_id: int, user_id: int, password_hash: str) -> None: ...


@dataclass(frozen=True)
class SetPasswordRequest:
    token: str
    new_password: str


def set_password(repo: SetPasswordRepository, req: SetPasswordRequest) -> None:
    token = req.token.strip() if req.token else ""
    if not token:
        raise ValidationError("Token inválido o expirado.")

    user = repo.find_user_by_verification_token(token=token)
    if user is None:
        raise ValidationError("Token inválido o expirado.")

    # Validate password strength
    validate_password_strength(req.new_password)

    password_hash = hash_password(req.new_password)
    repo.set_invited_employee_password(
        company_id=user.company_id,
        user_id=user.id,
        password_hash=password_hash,
    )
