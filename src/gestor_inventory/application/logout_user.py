from dataclasses import dataclass
import hashlib
import json
import time
from typing import Protocol

from gestor_inventory.domain.errors import RefreshTokenInvalidError, ValidationError


class LogoutRepository(Protocol):
    def invalidate_refresh_token(self, *, company_id: int, token_hash: str, now: int) -> tuple[str, int | None]: ...

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
class LogoutRequest:
    company_id: int
    refresh_token: str


def logout_user(repo: LogoutRepository, req: LogoutRequest, *, now: int | None = None) -> None:
    company_id = _validate_company_id(req.company_id)
    refresh_token = _validate_refresh_token(req.refresh_token)
    now_v = int(time.time()) if now is None else int(now)

    status, user_id = repo.invalidate_refresh_token(
        company_id=company_id,
        token_hash=_hash_token(refresh_token),
        now=now_v,
    )
    if status != "ok":
        repo.create_audit_log(
            company_id=company_id,
            branch_id=None,
            user_id=int(user_id) if isinstance(user_id, int) else None,
            event_type="auth.logout",
            created_at=now_v,
            metadata_json=json.dumps({"success": False, "reason": status}, separators=(",", ":")),
        )
        raise RefreshTokenInvalidError()

    repo.create_audit_log(
        company_id=company_id,
        branch_id=None,
        user_id=int(user_id) if isinstance(user_id, int) else None,
        event_type="auth.logout",
        created_at=now_v,
        metadata_json=json.dumps({"success": True}, separators=(",", ":")),
    )


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_refresh_token(refresh_token: str) -> str:
    if not isinstance(refresh_token, str):
        raise ValidationError("refresh_token inválido")
    value = refresh_token.strip()
    if not value:
        raise ValidationError("refresh_token inválido")
    return value
