"""Structured audit logger with cryptographic hash chaining and tamper detection."""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import sqlite3
from typing import Any

from quantumvault.storage.repositories import AuditRepository

GENESIS_PREV_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


def compute_entry_hash(prev_hash: str, request_id: str, event_time_utc: str,
                       actor_id: str, op: str, asset_id: str | None,
                       decision: str, rule: str) -> str:
    """Compute deterministic SHA-256 integrity hash linking previous block hash to current event."""
    canonical = f"{prev_hash}|{request_id}|{event_time_utc}|{actor_id}|{op}|{asset_id or ''}|{decision}|{rule}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLogger:
    """Records immutable audit decisions into a cryptographically linked hash chain."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.repo = AuditRepository(conn)

    def log_decision(self, request_id: str, actor_id: str, op: str, asset_id: str | None,
                     decision: str, rule: str) -> str:
        """Record an access decision into the verifiable hash chain.
        
        Returns:
            The calculated entry_hash for this record.
        """
        now_utc = datetime.now(timezone.utc).isoformat()

        # Query previous record's entry hash to form cryptographic link
        last_entry = self.repo.get_last_entry()
        prev_hash = last_entry["entry_hash"] if last_entry else GENESIS_PREV_HASH

        entry_hash = compute_entry_hash(
            prev_hash=prev_hash,
            request_id=request_id,
            event_time_utc=now_utc,
            actor_id=actor_id,
            op=op,
            asset_id=asset_id,
            decision=decision,
            rule=rule
        )

        self.repo.record(
            request_id=request_id,
            event_time_utc=now_utc,
            actor_id=actor_id,
            op=op,
            asset_id=asset_id,
            decision=decision,
            rule=rule,
            entry_hash=entry_hash,
            prev_hash=prev_hash
        )

        return entry_hash

    def get_record(self, request_id: str) -> dict[str, Any] | None:
        """Lookup historical decision by request ID."""
        return self.repo.get(request_id)

    def get_chain(self, start_seq: int = 1, limit: int | None = None) -> list[dict[str, Any]]:
        """Retrieve audit chain starting at specified sequence number."""
        return self.repo.get_chain(start_seq=start_seq, limit=limit)

    def get_total_count(self) -> int:
        """Return total count of audit events."""
        return self.repo.count()
