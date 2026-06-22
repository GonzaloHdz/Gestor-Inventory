from dataclasses import dataclass


@dataclass(frozen=True)
class CompanySetting:
    id: int
    company_id: int
    setting_key: str
    setting_value: str
    created_at: int
    updated_at: int
