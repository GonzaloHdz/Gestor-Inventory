import hashlib
import time
from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.errors import PasswordResetTokenExpiredError, PasswordResetTokenInvalidError, ValidationError
from gestor_inventory.security.password_hash import hash_password


class PasswordResetConsumeRepository(Protocol):
    def consume_password_reset_token_and_update_password(
        self,
        *,
        company_id: int,
        token_hash: str,
        new_password_hash: str,
        now: int,
    ) -> str: ...


@dataclass(frozen=True)
class ResetPasswordRequest:
    company_id: int
    token: str
    new_password: str


def reset_password(
    repo: PasswordResetConsumeRepository,
    req: ResetPasswordRequest,
    *,
    now: int | None = None,
) -> None:
    company_id = _validate_company_id(req.company_id)
    token = _validate_token(req.token)
    new_password = _validate_password(req.new_password)
    now_v = int(time.time()) if now is None else int(now)

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    new_password_hash = hash_password(new_password)
    status = repo.consume_password_reset_token_and_update_password(
        company_id=company_id,
        token_hash=token_hash,
        new_password_hash=new_password_hash,
        now=now_v,
    )
    if status == "ok":
        return
    if status == "expired":
        raise PasswordResetTokenExpiredError()
    raise PasswordResetTokenInvalidError()


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_token(token: str) -> str:
    if not isinstance(token, str):
        raise ValidationError("token inválido")
    token_v = token.strip()
    if not token_v:
        raise ValidationError("token inválido")
    return token_v


def _validate_password(password: str) -> str:
    if not isinstance(password, str) or not password:
        raise ValidationError("password inválido")
    return password
