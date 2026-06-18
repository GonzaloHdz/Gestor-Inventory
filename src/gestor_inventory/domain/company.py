from dataclasses import dataclass


@dataclass(frozen=True)
class Company:
    id: int
    name: str
    currency: str
    timezone: str
    status: str
    default_branch_id: int | None
    created_at: int
