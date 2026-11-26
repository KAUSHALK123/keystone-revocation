"""Central Security Authority managing global epochs, active keys, and revocation truth."""
import hashlib
from pathlib import Path
import sqlite3
import time
from typing import Any

from quantumvault.config import get_db_path, get_epoch_anchor_path, get_state_dir
from quantumvault.core.errors import StateError
from quantumvault.storage.atomic import atomic_write_text
from quantumvault.storage.db import get_connection, init_db, transaction
from quantumvault.storage.repositories import (
    ClusterEpochRepository,
    KeyVersionRepository,
    RevocationRepository,
)


def _anchor_digest(epoch: int) -> str:
    return hashlib.sha256(f"qv-epoch-anchor:{epoch}".encode("utf-8")).hexdigest()


def write_epoch_anchor(state_dir: Path, epoch: int) -> None:
    """Persist monotonic epoch anchor atomically outside the SQLite database file."""
    anchor_path = get_epoch_anchor_path(state_dir)
    current = read_epoch_anchor(state_dir)
    if epoch > current or (epoch >= 1 and not anchor_path.exists()):
        payload = f"v1:{epoch}:{_anchor_digest(epoch)}"
        atomic_write_text(anchor_path, payload, encoding="utf-8")


def read_epoch_anchor(state_dir: Path) -> int:
    """Read external monotonic epoch anchor, failing closed on corruption."""
    anchor_path = get_epoch_anchor_path(state_dir)
    if not anchor_path.exists():
        return 1
    try:
        raw = anchor_path.read_text(encoding="utf-8").strip()
    except OSError as e:
        raise StateError(f"Unable to read external cluster epoch anchor: {e}") from e

    if not raw:
        raise StateError("Corrupted external cluster epoch anchor: empty file")

    if raw.startswith("v1:"):
        parts = raw.split(":")
        if len(parts) != 3:
            raise StateError("Corrupted external cluster epoch anchor: malformed record")
        try:
            epoch = int(parts[1])
        except ValueError as e:
            raise StateError("Corrupted external cluster epoch anchor: invalid epoch") from e
        if epoch < 1 or parts[2] != _anchor_digest(epoch):
            raise StateError("Corrupted external cluster epoch anchor: integrity check failed")
        return epoch

    # Legacy plain integer anchor compatibility
    try:
        epoch = int(raw)
        if epoch < 1:
            raise ValueError("epoch < 1")
        return epoch
    except ValueError as e:
        raise StateError("Corrupted external cluster epoch anchor: invalid content") from e


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
        write_epoch_anchor(self.state_dir, self.epoch_repo.get_current_epoch())

    def get_current_epoch(self) -> int:
        """Query monotonic cluster epoch counter."""
        return max(self.epoch_repo.get_current_epoch(), read_epoch_anchor(self.state_dir))

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
        write_epoch_anchor(self.state_dir, new_epoch)

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
