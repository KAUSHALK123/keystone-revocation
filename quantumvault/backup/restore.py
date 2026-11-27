"""Authenticated backup verification, anti-rollback protection, and safe restoration."""
import hashlib
import hmac
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
from typing import Any

from quantumvault.backup.backup_manager import (
    FORMAT_VERSION,
    MAGIC_HEADER,
    _derive_backup_keys,
)
from quantumvault.config import get_db_path, get_state_dir, get_vault_key_path
from quantumvault.core.errors import CryptoError, StateError
from quantumvault.crypto.encryption import AuthenticatedEncryption
from quantumvault.crypto.key_manager import load_vault_key
from quantumvault.distributed.authority import read_epoch_anchor, write_epoch_anchor
from quantumvault.storage.repositories import ClusterEpochRepository


class BackupRestoreManager:
    """Verifies HMAC integrity, enforces monotonic anti-rollback policy, and restores databases."""

    def __init__(self, db_path: Path | None = None, state_dir: Path | None = None,
                 backup_key: bytes | None = None):
        self.state_dir = state_dir or get_state_dir()
        self.db_path = db_path or get_db_path(self.state_dir)
        raw_master = backup_key or load_vault_key(get_vault_key_path(self.state_dir))
        self.enc_key, self.hmac_key = _derive_backup_keys(raw_master)

    def get_current_cluster_epoch(self) -> int:
        """Query the highest known monotonic cluster epoch across DB and external anchor."""
        anchor_epoch = read_epoch_anchor(self.state_dir)
        if not self.db_path.exists():
            return anchor_epoch
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            epoch_repo = ClusterEpochRepository(conn)
            epoch = epoch_repo.get_current_epoch()
            conn.close()
            return max(epoch, anchor_epoch)
        except Exception:
            return anchor_epoch

    def verify_and_restore(self, backup_file_path: Path, force_allow_rollback: bool = False,
                           expected_min_epoch: int | None = None) -> dict[str, Any]:
        """Verify package integrity, enforce anti-rollback constraints, and safely restore state."""
        if not backup_file_path.exists():
            raise StateError(f"Backup file not found: {backup_file_path}")

        raw_package = backup_file_path.read_bytes()

        # 1. Verify Magic
        if len(raw_package) < 52:  # 4(magic) + 4(len) + min_header + 12(nonce) + 32(hmac)
            raise CryptoError("Malformed backup file: size too small")

        magic = raw_package[:4]
        if magic != MAGIC_HEADER:
            raise CryptoError(f"Invalid backup magic bytes: expected {MAGIC_HEADER!r}, got {magic!r}")

        # 2. Parse Header Length and Header
        header_len = int.from_bytes(raw_package[4:8], byteorder="big")
        header_end = 8 + header_len
        if len(raw_package) < header_end + 12 + 32:
            raise CryptoError("Malformed backup file: truncated header or body")

        header_bytes = raw_package[8:header_end]
        try:
            header_dict = json.loads(header_bytes.decode("utf-8"))
        except Exception as e:
            raise CryptoError(f"Invalid JSON in backup header: {e}") from e

        # 3. Extract Nonce, HMAC, and Ciphertext
        nonce = raw_package[header_end:header_end + 12]
        mac = raw_package[header_end + 12:header_end + 44]
        ciphertext = raw_package[header_end + 44:]

        # 4. Verify HMAC-SHA-256
        expected_mac = hmac.new(
            self.hmac_key,
            header_bytes + nonce + ciphertext,
            hashlib.sha256
        ).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise CryptoError("Backup HMAC verification failed: archive has been tampered with or corrupted")

        # 5. Anti-Rollback Verification:
        backup_epoch = int(header_dict.get("cluster_epoch", 0))
        current_epoch = expected_min_epoch if expected_min_epoch is not None else self.get_current_cluster_epoch()

        if backup_epoch < current_epoch and not force_allow_rollback:
            raise StateError(
                f"Rollback attack rejected: backup epoch {backup_epoch} is strictly older than current authority epoch {current_epoch}"
            )

        # 6. Authenticated Decryption
        cipher = AuthenticatedEncryption(self.enc_key)
        try:
            decrypted_snapshot = cipher.decrypt_bytes(ciphertext, nonce, associated_data=header_bytes)
        except Exception as e:
            raise CryptoError(f"Backup ciphertext authentication failed: {e}") from e

        # 7. Verify Content Hash
        calculated_sha = hashlib.sha256(decrypted_snapshot).hexdigest()
        expected_sha = header_dict.get("snapshot_sha256")
        if calculated_sha != expected_sha:
            raise CryptoError(f"Snapshot SHA-256 mismatch: expected {expected_sha}, got {calculated_sha}")

        # 8. Restore to target database safely via temporary staging file and integrity check
        # Pre-capture active security invariants to prevent resurrection across rollback
        active_revocations: list[dict[str, Any]] = []
        active_retired_keys: list[str] = []
        current_anchor_epoch = read_epoch_anchor(self.state_dir)
        highest_epoch = max(backup_epoch, current_anchor_epoch, current_epoch)

        if self.db_path.exists():
            try:
                curr_conn = sqlite3.connect(str(self.db_path))
                curr_conn.row_factory = sqlite3.Row
                cur = curr_conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='revocations'")
                if cur.fetchone():
                    cur.execute("SELECT actor_id, entity_type, reason, revoked_at FROM revocations")
                    active_revocations = [dict(r) for r in cur.fetchall()]

                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='key_versions'")
                if cur.fetchone():
                    cur.execute("SELECT version_id FROM key_versions WHERE status = 'retired'")
                    active_retired_keys = [r["version_id"] for r in cur.fetchall()]
                curr_conn.close()
            except Exception:
                pass

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_staging:
            tmp_staging_path = Path(tmp_staging.name)

        try:
            tmp_staging_path.write_bytes(decrypted_snapshot)

            # Check SQLite integrity of restored image
            conn = sqlite3.connect(str(tmp_staging_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("PRAGMA integrity_check;")
            row = cursor.fetchone()
            if not row or row[0] != "ok":
                conn.close()
                raise StateError(f"Restored SQLite snapshot failed integrity check: {row}")

            # Apply safe restoration invariants: preserve active revocations and retired keys
            try:
                with conn:
                    cur = conn.cursor()
                    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='revocations'")
                    if cur.fetchone() and active_revocations:
                        for r in active_revocations:
                            conn.execute(
                                """
                                INSERT OR REPLACE INTO revocations (actor_id, entity_type, reason, revoked_at)
                                VALUES (?, ?, ?, ?)
                                """,
                                (r["actor_id"], r.get("entity_type", "actor"),
                                 r.get("reason", "preservation_across_restore"), r.get("revoked_at", ""))
                            )

                    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='key_versions'")
                    if cur.fetchone() and active_retired_keys:
                        for vid in active_retired_keys:
                            conn.execute("UPDATE key_versions SET status = 'retired' WHERE version_id = ?", (vid,))

                    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cluster_epoch'")
                    if cur.fetchone():
                        epoch_repo = ClusterEpochRepository(conn)
                        if highest_epoch > epoch_repo.get_current_epoch():
                            conn.execute(
                                """
                                INSERT INTO cluster_epoch (epoch_counter, revocation_hash, committed_at)
                                VALUES (?, 'restored_epoch_anchor', CURRENT_TIMESTAMP)
                                """,
                                (highest_epoch,)
                            )
            finally:
                conn.close()

            # Write trusted external epoch anchor BEFORE overwriting database
            # This ensures that even if restoration is interrupted during copy, the monotonic epoch anchor is preserved
            write_epoch_anchor(self.state_dir, highest_epoch)

            # Overwrite active database file
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(tmp_staging_path, self.db_path)

            # Remove existing WAL and SHM files to prevent mixing old WAL with restored DB
            wal_path = self.db_path.with_name(self.db_path.name + "-wal")
            shm_path = self.db_path.with_name(self.db_path.name + "-shm")
            try:
                if wal_path.exists():
                    wal_path.unlink()
            except OSError:
                pass
            try:
                if shm_path.exists():
                    shm_path.unlink()
            except OSError:
                pass

        finally:
            if tmp_staging_path.exists():
                try:
                    tmp_staging_path.unlink()
                except OSError:
                    pass

        write_epoch_anchor(self.state_dir, highest_epoch)

        return {
            "restored": True,
            "cluster_epoch": highest_epoch,
            "original_backup_epoch": backup_epoch,
            "timestamp": header_dict.get("timestamp"),
            "snapshot_sha256": calculated_sha
        }

    def verify_backup(self, backup_path: Path | None = None, **kwargs: Any) -> bool:
        """Validate backup archive format and cryptographic integrity without restoring."""
        target = (
            backup_path
            or kwargs.get("path")
            or kwargs.get("archive_path")
            or kwargs.get("source_path")
            or kwargs.get("file_path")
        )
        if not target or not Path(target).is_file():
            return False
        try:
            raw = Path(target).read_bytes()
            if len(raw) < 52 or raw[:4] != MAGIC_HEADER:
                return False
            header_len = int.from_bytes(raw[4:8], byteorder="big")
            header_end = 8 + header_len
            if len(raw) < header_end + 44:
                return False
            header_bytes = raw[8:header_end]
            json.loads(header_bytes.decode("utf-8"))
            nonce = raw[header_end:header_end + 12]
            mac = raw[header_end + 12:header_end + 44]
            ciphertext = raw[header_end + 44:]
            expected_mac = hmac.new(self.hmac_key, header_bytes + nonce + ciphertext, hashlib.sha256).digest()
            if not hmac.compare_digest(mac, expected_mac):
                return False
            cipher = AuthenticatedEncryption(self.enc_key)
            cipher.decrypt_bytes(ciphertext, nonce, associated_data=header_bytes)
            return True
        except Exception:
            return False
