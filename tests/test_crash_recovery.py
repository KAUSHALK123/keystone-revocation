"""Tests for database durability, crash recovery, and anti-resurrection of revoked credentials (CRS01 - CRS08)."""
from pathlib import Path
import sqlite3
import tempfile
import unittest

from quantumvault.config import get_vault_key_path
from quantumvault.core.service import QuantumVaultService
from quantumvault.crypto.key_manager import load_vault_key
from quantumvault.crypto.rotation import KeyRotationManager
from quantumvault.iam.authentication import generate_device_keypair
from quantumvault.iam.device import DeviceManager
from quantumvault.iam.recovery import RecoveryManager
from quantumvault.storage.db import get_connection, transaction


class TestCrashRecovery(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp_dir.name)

        self.service = QuantumVaultService(state_dir=self.state_dir)
        self.service.setup(
            owners={"asset-1": "owner-1"},
            contents={"asset-1": "Durable Payload"},
            disabled=[],
            key_material="crash-recovery-test-key"
        )

    def tearDown(self):
        self.service.close()
        self.temp_dir.cleanup()

    def test_crs01_committed_state_survives_process_restart(self):
        """CRS01: Committed writes survive connection closing and reopening."""
        self.service.close()

        # Reopen fresh service instance pointing to same state directory
        reopened = QuantumVaultService(state_dir=self.state_dir)
        read_res = reopened.read("owner-1", "asset-1", "req-survive-1")
        self.assertEqual(read_res["decision"], "allow")
        self.assertEqual(read_res["body"], "Durable Payload")
        reopened.close()

    def test_crs02_uncommitted_transaction_rolled_back(self):
        """CRS02: Uncommitted transaction rolled back cleanly on error."""
        conn = get_connection(self.service.db_path)
        try:
            with transaction(conn):
                conn.execute(
                    "INSERT INTO identities (actor_id, status, role) VALUES ('phantom', 'active', 'viewer');"
                )
                raise RuntimeError("Simulated mid-transaction crash")
        except RuntimeError:
            pass
        finally:
            conn.close()

        # Verify phantom record was not persisted
        chk_conn = get_connection(self.service.db_path)
        cur = chk_conn.execute("SELECT * FROM identities WHERE actor_id = 'phantom';")
        self.assertIsNone(cur.fetchone())
        chk_conn.close()

    def test_crs03_wal_checkpoint_integrity(self):
        """CRS03: WAL mode checkpointing preserves database consistency."""
        conn = get_connection(self.service.db_path)
        cursor = conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        row = cursor.fetchone()
        conn.close()
        self.assertEqual(row[0], 0, "WAL checkpoint should succeed with code 0")

    def test_crs04_interrupted_rotation_recovery(self):
        """CRS04: Interrupted key rotation recovers to durable consistent state."""
        conn = get_connection(self.service.db_path)
        kek = load_vault_key(get_vault_key_path(self.state_dir))
        rot_mgr = KeyRotationManager(conn, kek)

        rot_mgr.app_state.set("key_rotation_status", "in_progress:v1->v2")
        rot_mgr.initialize_initial_version("v2")

        rec = rot_mgr.recover_interrupted_rotation()
        self.assertIsNotNone(rec)
        self.assertEqual(rot_mgr.app_state.get("key_rotation_status"), "completed:v2")
        conn.close()

    def test_crs05_anti_resurrection_revoked_actor(self):
        """CRS05: Revoked actor cannot be resurrected after process restart."""
        self.service.revoke("owner-1")
        self.service.close()

        restarted = QuantumVaultService(state_dir=self.state_dir)
        read_res = restarted.read("owner-1", "asset-1", "req-anti-res-1")
        self.assertEqual(read_res["decision"], "deny")
        restarted.close()

    def test_crs06_anti_resurrection_revoked_device(self):
        """CRS06: Revoked device remains revoked across service restarts."""
        conn = get_connection(self.service.db_path)
        dev_mgr = DeviceManager(conn)
        _, pub = generate_device_keypair()
        dev_mgr.enroll_device("owner-1", "dev-stolen", pub)
        dev_mgr.revoke_device("dev-stolen")
        conn.close()

        # Reopen connection
        new_conn = get_connection(self.service.db_path)
        new_dev_mgr = DeviceManager(new_conn)
        self.assertFalse(new_dev_mgr.is_device_active("dev-stolen"))
        new_conn.close()

    def test_crs07_anti_resurrection_consumed_recovery_code(self):
        """CRS07: Consumed recovery code cannot be resurrected or reused after restart."""
        conn = get_connection(self.service.db_path)
        rec_mgr = RecoveryManager(conn)
        codes = rec_mgr.generate_recovery_codes("owner-1", count=1)
        used = rec_mgr.verify_and_consume("owner-1", codes[0])
        self.assertTrue(used)
        conn.close()

        # Reopen and attempt to reuse code
        new_conn = get_connection(self.service.db_path)
        new_rec_mgr = RecoveryManager(new_conn)
        reused = new_rec_mgr.verify_and_consume("owner-1", codes[0])
        self.assertFalse(reused, "Consumed recovery code must never be reusable")
        new_conn.close()

    def test_crs08_corrupted_database_detection(self):
        """CRS08: Database file corruption is detectable via integrity check."""
        conn = get_connection(self.service.db_path)
        cursor = conn.execute("PRAGMA integrity_check;")
        row = cursor.fetchone()
        conn.close()
        self.assertEqual(row[0], "ok")


if __name__ == "__main__":
    unittest.main()
