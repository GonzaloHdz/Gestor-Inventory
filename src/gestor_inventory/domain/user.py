from dataclasses import dataclass


@dataclass(frozen=True)
class User:
    id: int
    company_id: int
    email: str
    password_hash: str
    is_active: bool
    verified: bool
    verification_token: str | None = None
