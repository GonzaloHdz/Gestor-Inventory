from dataclasses import dataclass


@dataclass(frozen=True)
class Company:
    id: int
    name: str
    currency: str
    timezone: str
    status: str
    created_at: int
