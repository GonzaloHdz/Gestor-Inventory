from dataclasses import dataclass


@dataclass(frozen=True)
class PurchaseOrder:
    company_id: int
    id: int
    supplier_id: int
    status: str
    created_at: int
    updated_at: int

    def __post_init__(self) -> None:
        if not isinstance(self.company_id, int) or self.company_id <= 0:
            raise ValueError("company_id inválido")
        if not isinstance(self.supplier_id, int) or self.supplier_id <= 0:
            raise ValueError("supplier_id inválido")
        if not isinstance(self.status, str) or self.status not in ("created", "approved", "cancelled"):
            raise ValueError("status inválido")
