"""Consistent SQLite snapshot and authenticated backup creation with anti-rollback metadata."""
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
import tempfile
from typing import Any

from quantumvault.config import get_db_path, get_state_dir, get_vault_key_path
from quantumvault.core.errors import CryptoError, StateError
from quantumvault.crypto.encryption import AuthenticatedEncryption
from quantumvault.crypto.key_manager import load_vault_key
from quantumvault.storage.repositories import ClusterEpochRepository

MAGIC_HEADER = b"QVBK"
FORMAT_VERSION = 1


def _derive_backup_keys(master_key: bytes) -> tuple[bytes, bytes]:
    """Derive independent encryption and HMAC keys from the master key."""
    enc_key = hashlib.sha256(master_key + b":backup-encryption").digest()
    hmac_key = hashlib.sha256(master_key + b":backup-hmac").digest()
    return enc_key, hmac_key


class BackupManager:
    """Creates authenticated, tamper-evident, encrypted database backups containing monotonic epochs."""

    def __init__(self, db_path: Path | None = None, state_dir: Path | None = None,
                 backup_key: bytes | None = None):
        self.state_dir = state_dir or get_state_dir()
        self.db_path = db_path or get_db_path(self.state_dir)
        raw_master = backup_key or load_vault_key(get_vault_key_path(self.state_dir))
        self.enc_key, self.hmac_key = _derive_backup_keys(raw_master)

    def create_backup(self, target_backup_path: Path) -> dict[str, Any]:
        """Create a consistent online database snapshot, encrypt with AES-256-GCM, and authenticate with HMAC."""
        target_backup_path.parent.mkdir(parents=True, exist_ok=True)

        # 1. Take a consistent online backup using SQLite's backup API
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_file:
            tmp_snapshot_path = Path(tmp_file.name)

        try:
            src_conn = sqlite3.connect(str(self.db_path))
            dest_conn = sqlite3.connect(str(tmp_snapshot_path))
            try:
                src_conn.backup(dest_conn)
            finally:
                dest_conn.close()
                src_conn.close()

            # Query current cluster epoch from the consistent snapshot
            chk_conn = sqlite3.connect(str(tmp_snapshot_path))
            chk_conn.row_factory = sqlite3.Row
            epoch_repo = ClusterEpochRepository(chk_conn)
            current_epoch = epoch_repo.get_current_epoch()
            chk_conn.close()

            snapshot_bytes = tmp_snapshot_path.read_bytes()
            snapshot_sha256 = hashlib.sha256(snapshot_bytes).hexdigest()
        finally:
            if tmp_snapshot_path.exists():
                try:
                    tmp_snapshot_path.unlink()
                except OSError:
                    pass

        # 2. Construct authenticated metadata header
        now_iso = datetime.now(timezone.utc).isoformat()
        header_dict = {
            "magic": "QVBK",
            "version": FORMAT_VERSION,
            "cluster_epoch": current_epoch,
            "timestamp": now_iso,
            "snapshot_sha256": snapshot_sha256,
            "snapshot_size_bytes": len(snapshot_bytes)
        }
        header_bytes = json.dumps(header_dict, sort_keys=True).encode("utf-8")

        # 3. Encrypt snapshot bytes under AES-256-GCM with AAD binding the header
        cipher = AuthenticatedEncryption(self.enc_key)
        ciphertext, nonce = cipher.encrypt(snapshot_bytes, associated_data=header_bytes)

        # 4. Compute HMAC-SHA-256 over (header_bytes + nonce + ciphertext)
        mac = hmac.new(self.hmac_key, header_bytes + nonce + ciphertext, hashlib.sha256).digest()

        # 5. Pack package: [MAGIC 4B][HEADER_LEN 4B][HEADER][NONCE 12B][HMAC 32B][CIPHERTEXT]
        header_len = len(header_bytes)
        package = (
            MAGIC_HEADER +
            header_len.to_bytes(4, byteorder="big") +
            header_bytes +
            nonce +
            mac +
            ciphertext
        )

        target_backup_path.write_bytes(package)

        return {
            "backup_path": str(target_backup_path),
            "cluster_epoch": current_epoch,
            "timestamp": now_iso,
            "snapshot_sha256": snapshot_sha256,
            "backup_size_bytes": len(package)
        }
