from dataclasses import dataclass


@dataclass(frozen=True)
class Role:
    company_id: int
    id: int
    name: str
    is_system: bool


@dataclass(frozen=True)
class Permission:
    id: int
    code: str
    description: str | None

