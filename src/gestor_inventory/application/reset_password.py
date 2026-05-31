import hashlib
import json
import time
from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.errors import PasswordResetTokenExpiredError, PasswordResetTokenInvalidError, ValidationError
from gestor_inventory.security.password_hash import hash_password
from gestor_inventory.security.password_policy import validate_password_strength


class PasswordResetConsumeRepository(Protocol):
    def consume_password_reset_token_and_update_password(
        self,
        *,
        company_id: int,
        token_hash: str,
        new_password_hash: str,
        now: int,
    ) -> tuple[str, int | None]: ...

    def create_audit_log(
        self,
        *,
        company_id: int,
        branch_id: int | None,
        user_id: int | None,
        event_type: str,
        created_at: int,
        metadata_json: str | None,
    ) -> None: ...


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
    status, user_id = repo.consume_password_reset_token_and_update_password(
        company_id=company_id,
        token_hash=token_hash,
        new_password_hash=new_password_hash,
        now=now_v,
    )
    if status == "ok":
        repo.create_audit_log(
            company_id=company_id,
            branch_id=None,
            user_id=user_id,
            event_type="auth.password_reset_confirm",
            created_at=now_v,
            metadata_json=json.dumps({"status": "ok"}, separators=(",", ":")),
        )
        return
    if status == "expired":
        repo.create_audit_log(
            company_id=company_id,
            branch_id=None,
            user_id=user_id,
            event_type="auth.password_reset_confirm",
            created_at=now_v,
            metadata_json=json.dumps({"status": "expired"}, separators=(",", ":")),
        )
        raise PasswordResetTokenExpiredError()
    repo.create_audit_log(
        company_id=company_id,
        branch_id=None,
        user_id=user_id,
        event_type="auth.password_reset_confirm",
        created_at=now_v,
        metadata_json=json.dumps({"status": status}, separators=(",", ":")),
    )
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
    validate_password_strength(password)
    return str(password)
