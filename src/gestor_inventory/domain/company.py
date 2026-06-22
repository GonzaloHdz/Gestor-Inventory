from dataclasses import dataclass

from gestor_inventory.domain.errors import ValidationError


@dataclass(frozen=True)
class Company:
    id: int
    name: str
    currency: str
    timezone: str
    status: str
    default_branch_id: int | None
    created_at: int


ALLOWED_COMPANY_SETTING_KEYS = {"moneda", "stock_minimo", "notificaciones_activas"}


def normalize_company_setting_value(*, setting_key: str, raw_value: object) -> str:
    if setting_key not in ALLOWED_COMPANY_SETTING_KEYS:
        raise ValidationError(f"Llave de configuración no permitida: {setting_key}")

    if setting_key == "moneda":
        if not isinstance(raw_value, str):
            raise ValidationError("moneda debe ser un string de 3 letras")
        v = raw_value.strip().upper()
        if len(v) != 3 or not v.isalpha():
            raise ValidationError("moneda debe ser un string de 3 letras")
        return v

    if setting_key == "stock_minimo":
        try:
            v = int(raw_value) if not isinstance(raw_value, bool) else None
        except Exception:
            v = None
        if v is None or v <= 0:
            raise ValidationError("stock_minimo debe ser numérico")
        return str(v)

    if setting_key == "notificaciones_activas":
        if isinstance(raw_value, bool):
            return "true" if raw_value else "false"
        if isinstance(raw_value, str):
            v = raw_value.strip().lower()
            if v in ("true", "false"):
                return v
        raise ValidationError("notificaciones_activas debe ser booleano")

    raise ValidationError(f"Llave de configuración no permitida: {setting_key}")
