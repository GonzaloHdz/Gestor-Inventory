import json
import time
from dataclasses import dataclass
from typing import Protocol

from gestor_inventory.domain.errors import ValidationError


class CompanySettingsWriteRepository(Protocol):
    def upsert_company_setting(self, *, company_id: int, setting_key: str, setting_value: str, now: int) -> None: ...


@dataclass(frozen=True)
class UpdateCompanySettingsRequest:
    company_id: int
    settings: dict[str, object]


def update_company_settings(
    repo: CompanySettingsWriteRepository,
    req: UpdateCompanySettingsRequest,
    *,
    now: int | None = None,
) -> None:
    company_id = _validate_company_id(req.company_id)
    if not isinstance(req.settings, dict):
        raise ValidationError("settings inválido")
    now_v = int(time.time()) if now is None else int(now)

    for raw_key, raw_value in req.settings.items():
        key = _validate_key(raw_key)
        value = _normalize_value(raw_value)
        repo.upsert_company_setting(company_id=company_id, setting_key=key, setting_value=value, now=now_v)


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_key(key: object) -> str:
    if not isinstance(key, str):
        raise ValidationError("setting_key inválido")
    v = key.strip()
    if not v:
        raise ValidationError("setting_key inválido")
    if len(v) > 128:
        raise ValidationError("setting_key inválido")
    return v


def _normalize_value(value: object) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
