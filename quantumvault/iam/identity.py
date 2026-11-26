"""Identity representation and management for QuantumVault."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Identity:
    actor_id: str
    status: str = "active"  # 'active' or 'disabled'
    role: str = "viewer"
    created_at: datetime | None = None

    @property
    def is_active(self) -> bool:
        return self.status == "active"
