import hashlib
import time
from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.errors import ValidationError


class EmailVerificationRepository(Protocol):
    def consume_email_verification_token_and_verify_user(
        self,
        *,
        company_id: int,
        token_hash: str,
        now: int,
    ) -> tuple[str, int | None]: ...


@dataclass(frozen=True)
class VerifyEmailRequest:
    company_id: int
    token: str


def verify_email(
    repo: EmailVerificationRepository,
    req: VerifyEmailRequest,
    *,
    now: int | None = None,
) -> None:
    company_id = _validate_company_id(req.company_id)
    token = _validate_token(req.token)
    now_v = int(time.time()) if now is None else int(now)

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    status, _user_id = repo.consume_email_verification_token_and_verify_user(
        company_id=company_id,
        token_hash=token_hash,
        now=now_v,
    )
    if status == "ok":
        return
    raise ValidationError("token inválido")


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

