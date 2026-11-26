"""External trusted checkpoints for verifiable audit log truncation detection."""
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import sqlite3
from typing import Any

from quantumvault.storage.db import transaction
from quantumvault.storage.repositories import AuditCheckpointRepository, AuditRepository

# Per-process fallback for purely in-memory SQLite databases when no external path exists
_MEMORY_FALLBACK_KEY = secrets.token_bytes(32)


def _resolve_checkpoint_key(conn: sqlite3.Connection,
                            external_file_path: Path | None = None) -> bytes:
    """Load or generate a CSPRNG HMAC key stored outside the SQLite database file."""
    key_dir: Path | None = None
    if external_file_path is not None:
        key_dir = external_file_path.parent
    else:
        try:
            rows = conn.execute("PRAGMA database_list;").fetchall()
            for r in rows:
                db_file = r[2] if len(r) > 2 else ""
                if db_file:
                    key_dir = Path(db_file).resolve().parent
                    break
        except sqlite3.Error:
            key_dir = None

    if key_dir is None:
        return _MEMORY_FALLBACK_KEY

    key_path = key_dir / ".audit_checkpoint.key"
    if key_path.exists():
        raw = key_path.read_bytes()
        if len(raw) == 32:
            return raw

    key_dir.mkdir(parents=True, exist_ok=True)
    raw = secrets.token_bytes(32)
    key_path.write_bytes(raw)
    return raw


def compute_checkpoint_hmac(checkpoint_id: str, sequence_up_to: int,
                            cumulative_hash: str, secret_key: bytes) -> str:
    """Compute HMAC-SHA-256 signature over checkpoint tuple."""
    payload = f"{checkpoint_id}:{sequence_up_to}:{cumulative_hash}".encode("utf-8")
    return hmac.new(secret_key, payload, hashlib.sha256).hexdigest()


class CheckpointManager:
    """Creates periodic signed checkpoints committing to the cumulative hash chain,
    persisting both to the database and an independent external file store.
    """

    def __init__(self, conn: sqlite3.Connection, secret_key: bytes | None = None,
                 external_file_path: Path | str | None = None):
        self.conn = conn
        self.external_file_path = Path(external_file_path) if external_file_path else None
        self.secret_key = secret_key or _resolve_checkpoint_key(conn, self.external_file_path)
        self.audit_repo = AuditRepository(conn)
        self.chk_repo = AuditCheckpointRepository(conn)

    def create_checkpoint(self, checkpoint_id: str | None = None) -> dict[str, Any] | None:
        """Create a signed checkpoint anchoring the current chain state."""
        last_entry = self.audit_repo.get_last_entry()
        if not last_entry:
            return None

        seq_up_to = last_entry["sequence_num"]
        cum_hash = last_entry["entry_hash"]
        chk_id = checkpoint_id or f"checkpoint-seq-{seq_up_to}"

        chk_hmac = compute_checkpoint_hmac(chk_id, seq_up_to, cum_hash, self.secret_key)

        with transaction(self.conn):
            self.chk_repo.create_checkpoint(
                checkpoint_id=chk_id,
                sequence_up_to=seq_up_to,
                cumulative_hash=cum_hash,
                checkpoint_hmac=chk_hmac
            )

        chk_record = {
            "checkpoint_id": chk_id,
            "sequence_up_to": seq_up_to,
            "cumulative_hash": cum_hash,
            "checkpoint_hmac": chk_hmac
        }

        # Persist externally to independent file
        if self.external_file_path:
            self._save_to_external_file(chk_record)

        return chk_record

    def _save_to_external_file(self, chk_record: dict[str, Any]) -> None:
        try:
            self.external_file_path.parent.mkdir(parents=True, exist_ok=True)
            existing: list[dict[str, Any]] = []
            if self.external_file_path.exists():
                try:
                    with open(self.external_file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            existing = data
                except Exception:
                    existing = []
            
            # Avoid duplicate checkpoint_id
            existing = [c for c in existing if c.get("checkpoint_id") != chk_record["checkpoint_id"]]
            existing.append(chk_record)
            with open(self.external_file_path, "w", encoding="utf-8") as f:
                json.dump(existing, f, indent=2)
        except OSError:
            pass

    def get_latest_checkpoint(self) -> dict[str, Any] | None:
        """Return the highest sequence checkpoint across DB and external file."""
        db_chk = self.chk_repo.get_latest_checkpoint()
        ext_chks = self.load_external_checkpoints()
        if not ext_chks:
            return db_chk
        ext_latest = max(ext_chks, key=lambda c: c.get("sequence_up_to", 0))
        if not db_chk or ext_latest.get("sequence_up_to", 0) > db_chk.get("sequence_up_to", 0):
            return ext_latest
        return db_chk

    def load_external_checkpoints(self) -> list[dict[str, Any]]:
        """Load checkpoints saved to external trusted file."""
        if not self.external_file_path or not self.external_file_path.exists():
            return []
        try:
            with open(self.external_file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
        except Exception:
            return []
        return []

    def list_checkpoints(self) -> list[dict[str, Any]]:
        """Return all checkpoints in ascending sequence order, unioning DB and external file."""
        db_chks = {c["checkpoint_id"]: c for c in self.chk_repo.list_checkpoints()}
        for ext in self.load_external_checkpoints():
            if ext.get("checkpoint_id") not in db_chks:
                db_chks[ext["checkpoint_id"]] = ext
        return sorted(db_chks.values(), key=lambda c: c["sequence_up_to"])

    def verify_checkpoint(self, checkpoint_dict: dict[str, Any]) -> bool:
        """Verify the cryptographic HMAC of a checkpoint."""
        chk_id = checkpoint_dict["checkpoint_id"]
        seq_up_to = checkpoint_dict["sequence_up_to"]
        cum_hash = checkpoint_dict["cumulative_hash"]
        claimed_hmac = checkpoint_dict["checkpoint_hmac"]

        expected_hmac = compute_checkpoint_hmac(chk_id, seq_up_to, cum_hash, self.secret_key)
        return hmac.compare_digest(claimed_hmac, expected_hmac)
