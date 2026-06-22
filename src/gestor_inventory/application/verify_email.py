import hashlib
import time
from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.application.verification_links import resolve_verification_token
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
    token: str
    company_id: int | None = None


def verify_email(
    repo: EmailVerificationRepository,
    req: VerifyEmailRequest,
    *,
    now: int | None = None,
) -> None:
    token = _validate_token(req.token)
    company_id, raw_token = resolve_verification_token(token=token, company_id=req.company_id)
    now_v = int(time.time()) if now is None else int(now)

    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    status, _user_id = repo.consume_email_verification_token_and_verify_user(
        company_id=company_id,
        token_hash=token_hash,
        now=now_v,
    )
    if status == "ok":
        return
    raise ValidationError("token inválido")
def _validate_token(token: str) -> str:
    if not isinstance(token, str):
        raise ValidationError("token inválido")
    token_v = token.strip()
    if not token_v:
        raise ValidationError("token inválido")
    return token_v

