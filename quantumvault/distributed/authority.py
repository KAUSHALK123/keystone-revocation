"""Central Security Authority managing global epochs, active keys, and revocation truth."""
import hashlib
from pathlib import Path
import sqlite3
import time
from typing import Any

from quantumvault.config import get_db_path, get_state_dir
from quantumvault.storage.db import get_connection, init_db, transaction
from quantumvault.storage.repositories import (
    ClusterEpochRepository,
    KeyVersionRepository,
    RevocationRepository,
)


class SecurityAuthority:
    """Authoritative trust anchor for cluster epochs and global revocations."""

    def __init__(self, state_dir: Path | None = None, db_path: Path | None = None):
        self.state_dir = state_dir or get_state_dir()
        self.db_path = db_path or get_db_path(self.state_dir)
        self.conn = get_connection(self.db_path)
        init_db(self.conn)
        self.epoch_repo = ClusterEpochRepository(self.conn)
        self.rev_repo = RevocationRepository(self.conn)
        self.key_repo = KeyVersionRepository(self.conn)

        # Initialize epoch 1 if empty
        with transaction(self.conn):
            self.epoch_repo.init_epoch(1, "genesis-epoch-hash")

    def get_current_epoch(self) -> int:
        """Query monotonic cluster epoch counter."""
        return self.epoch_repo.get_current_epoch()

    def compute_revocation_hash(self) -> str:
        """Compute deterministic SHA-256 hash over all active revocations."""
        revs = self.rev_repo.list_all()
        canonical_entries = [f"{r['actor_id']}:{r['entity_type']}" for r in revs]
        canonical_entries.sort()
        blob = "\n".join(canonical_entries).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def issue_revocation(self, entity_id: str, entity_type: str = "actor",
                         reason: str = "administrative_revocation") -> dict[str, Any]:
        """Commit an authoritative revocation and advance the global cluster epoch."""
        with transaction(self.conn):
            self.rev_repo.revoke(entity_id, entity_type=entity_type, reason=reason)
            rev_hash = self.compute_revocation_hash()
            new_epoch = self.epoch_repo.advance_epoch(revocation_hash=rev_hash)

        return {
            "epoch": new_epoch,
            "entity_id": entity_id,
            "entity_type": entity_type,
            "revocation_hash": rev_hash,
            "committed_at": time.time()
        }

    def get_all_revocations(self) -> set[tuple[str, str]]:
        """Return all authoritative revocations as a set of (id, type)."""
        revs = self.rev_repo.list_all()
        return {(r["actor_id"], r["entity_type"]) for r in revs}

    def get_active_key_version(self) -> str:
        """Return version_id of current active master key."""
        active = self.key_repo.get_active_version()
        return active["version_id"] if active else "v1"

    def close(self) -> None:
        """Close database connection cleanly."""
        try:
            self.conn.close()
        except Exception:
            pass
