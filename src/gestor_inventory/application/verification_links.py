from gestor_inventory.domain.errors import ValidationError


def build_verification_url(*, base_url: str, company_id: int, raw_token: str) -> str:
    token = compose_verification_token(company_id=company_id, raw_token=raw_token)
    return f"{base_url.rstrip('/')}/api/auth/verify?token={token}"


def compose_verification_token(*, company_id: int, raw_token: str) -> str:
    company_id_v = _validate_company_id(company_id)
    raw_token_v = _validate_raw_token(raw_token)
    return f"{company_id_v}.{raw_token_v}"


def resolve_verification_token(*, token: str, company_id: int | None = None) -> tuple[int, str]:
    token_v = _validate_raw_token(token)
    embedded_company_id, raw_token = _extract_embedded_company_id(token_v)
    if embedded_company_id is not None:
        return embedded_company_id, raw_token
    if company_id is None:
        raise ValidationError("token inválido")
    return _validate_company_id(company_id), token_v


def _extract_embedded_company_id(token: str) -> tuple[int | None, str]:
    prefix, sep, suffix = token.partition(".")
    if sep != ".":
        return None, token
    if not prefix.isdigit():
        return None, token
    company_id = int(prefix)
    if company_id <= 0:
        raise ValidationError("token inválido")
    raw_token = _validate_raw_token(suffix)
    return company_id, raw_token


def _validate_company_id(company_id: int) -> int:
    if not isinstance(company_id, int) or company_id <= 0:
        raise ValidationError("company_id inválido")
    return company_id


def _validate_raw_token(token: str) -> str:
    if not isinstance(token, str):
        raise ValidationError("token inválido")
    value = token.strip()
    if not value:
        raise ValidationError("token inválido")
    return value
