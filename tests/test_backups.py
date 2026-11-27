"""Tests for hot database backups, AES-GCM encryption, HMAC verification, and anti-rollback defense (BAK01 - BAK10)."""
from pathlib import Path
import tempfile
import unittest

from quantumvault.backup.backup_manager import BackupManager
from quantumvault.backup.restore import BackupRestoreManager
from quantumvault.config import get_vault_key_path
from quantumvault.core.errors import CryptoError, StateError
from quantumvault.core.service import QuantumVaultService
from quantumvault.crypto.key_manager import load_vault_key
from quantumvault.distributed.authority import SecurityAuthority


class TestBackups(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp_dir.name)

        self.service = QuantumVaultService(state_dir=self.state_dir)
        self.service.setup(
            owners={"confidential-doc": "agent-1"},
            contents={"confidential-doc": "Operational Blueprints"},
            disabled=[],
            key_material="backup-test-master-key-marker"
        )
        self.service.close()

        self.backup_mgr = BackupManager(state_dir=self.state_dir)
        self.restore_mgr = BackupRestoreManager(state_dir=self.state_dir)
        self.backup_file = self.state_dir / "backups" / "snapshot.qvb"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_bak01_hot_backup_creation_produces_archive(self):
        """BAK01: Hot backup creation creates valid encrypted archive."""
        meta = self.backup_mgr.create_backup(self.backup_file)
        self.assertTrue(self.backup_file.exists())
        self.assertGreater(meta["backup_size_bytes"], 0)
        self.assertEqual(meta["cluster_epoch"], 1)

    def test_bak02_backup_header_contains_metadata(self):
        """BAK02: Backup header contains epoch, timestamp, and SHA-256 digest."""
        meta = self.backup_mgr.create_backup(self.backup_file)
        self.assertIn("cluster_epoch", meta)
        self.assertIn("timestamp", meta)
        self.assertIn("snapshot_sha256", meta)
        self.assertEqual(len(meta["snapshot_sha256"]), 64)

    def test_bak03_backup_payload_is_encrypted(self):
        """BAK03: Raw backup archive is encrypted and does not contain plaintext marker."""
        self.backup_mgr.create_backup(self.backup_file)
        raw_bytes = self.backup_file.read_bytes()
        self.assertNotIn(b"Operational Blueprints", raw_bytes)
        self.assertNotIn(b"backup-test-master-key-marker", raw_bytes)

    def test_bak04_tampered_hmac_rejects_restore(self):
        """BAK04: Modifying the HMAC signature causes restoration to abort."""
        self.backup_mgr.create_backup(self.backup_file)
        data = bytearray(self.backup_file.read_bytes())
        # Tamper byte in HMAC region (approx offset 100)
        data[80] ^= 0xFF
        self.backup_file.write_bytes(data)

        with self.assertRaises(CryptoError):
            self.restore_mgr.verify_and_restore(self.backup_file)

    def test_bak05_tampered_ciphertext_rejects_restore(self):
        """BAK05: Modifying a byte in the ciphertext payload fails authentication."""
        self.backup_mgr.create_backup(self.backup_file)
        data = bytearray(self.backup_file.read_bytes())
        # Tamper last byte (in ciphertext payload)
        data[-1] ^= 0xAA
        self.backup_file.write_bytes(data)

        with self.assertRaises(CryptoError):
            self.restore_mgr.verify_and_restore(self.backup_file)

    def test_bak06_tampered_header_rejects_restore(self):
        """BAK06: Tampering with header metadata invalidates HMAC and rejects restore."""
        self.backup_mgr.create_backup(self.backup_file)
        data = bytearray(self.backup_file.read_bytes())
        # Tamper header region
        data[15] ^= 0x01
        self.backup_file.write_bytes(data)

        with self.assertRaises(CryptoError):
            self.restore_mgr.verify_and_restore(self.backup_file)

    def test_bak07_anti_rollback_rejects_older_epoch_backup(self):
        """BAK07: Restoring a backup with an older cluster epoch is rejected as a rollback attack."""
        # 1. Take backup at epoch 1
        self.backup_mgr.create_backup(self.backup_file)

        # 2. Advance system authority epoch to 2 by issuing a revocation
        authority = SecurityAuthority(state_dir=self.state_dir)
        authority.issue_revocation("agent-1", entity_type="actor")
        current_epoch = authority.get_current_epoch()
        self.assertEqual(current_epoch, 2)
        authority.close()

        # 3. Attempt to restore epoch-1 backup without force flag MUST raise StateError
        with self.assertRaises(StateError) as ctx:
            self.restore_mgr.verify_and_restore(self.backup_file, force_allow_rollback=False)
        self.assertIn("Rollback attack rejected", str(ctx.exception))

    def test_bak08_valid_backup_restores_cleanly(self):
        """BAK08: Valid backup matching current epoch restores cleanly."""
        self.backup_mgr.create_backup(self.backup_file)
        res = self.restore_mgr.verify_and_restore(self.backup_file)
        self.assertTrue(res["restored"])
        self.assertEqual(res["cluster_epoch"], 1)

    def test_bak09_restored_state_preserves_content_and_permissions(self):
        """BAK09: Restored database allows authorized reading of stored assets."""
        self.backup_mgr.create_backup(self.backup_file)
        self.restore_mgr.verify_and_restore(self.backup_file)

        svc = QuantumVaultService(state_dir=self.state_dir)
        read_res = svc.read("agent-1", "confidential-doc", "req-restore-read")
        self.assertEqual(read_res["decision"], "allow")
        self.assertEqual(read_res["body"], "Operational Blueprints")
        svc.close()

    def test_bak10_emergency_force_allows_authorized_disaster_recovery(self):
        """BAK10: Emergency recovery with force_allow_rollback=True succeeds when explicitly permitted."""
        self.backup_mgr.create_backup(self.backup_file)

        authority = SecurityAuthority(state_dir=self.state_dir)
        authority.issue_revocation("agent-1", entity_type="actor")
        authority.close()

        # Explicit disaster recovery override
        res = self.restore_mgr.verify_and_restore(self.backup_file, force_allow_rollback=True)
        self.assertTrue(res["restored"])

    def test_bak11_safe_restoration_anti_resurrection(self):
        """BAK11: Emergency rollback restoration does NOT resurrect revoked credentials."""
        # 1. Setup multi-user state and create valid backup
        svc = QuantumVaultService(state_dir=self.state_dir)
        svc.setup(
            owners={"doc-1": "user-a", "doc-2": "user-b"},
            contents={"doc-1": "Data A", "doc-2": "Data B"},
            disabled=[],
            key_material="backup-test-secret"
        )
        svc.close()
        self.backup_mgr.create_backup(self.backup_file)

        # 2. Revoke user-a
        svc = QuantumVaultService(state_dir=self.state_dir)
        svc.revoke("user-a")
        read_a_pre = svc.read("user-a", "doc-1", "req-rev-check")
        self.assertEqual(read_a_pre["decision"], "deny")
        svc.close()

        # 3. Restore older backup using force_allow_rollback=True
        res = self.restore_mgr.verify_and_restore(self.backup_file, force_allow_rollback=True)
        self.assertTrue(res["restored"])

        # 4. Reopen service (simulating restart) and verify:
        # - Revoked user-a is STILL DENIED (zero resurrection!)
        # - Unaffected user-b STILL HAS ACCESS to restored data
        svc_reopened = QuantumVaultService(state_dir=self.state_dir)
        read_a_post = svc_reopened.read("user-a", "doc-1", "req-post-restore-a")
        self.assertEqual(read_a_post["decision"], "deny", "Revoked user must NOT be resurrected by backup restore")

        read_b_post = svc_reopened.read("user-b", "doc-2", "req-post-restore-b")
        self.assertEqual(read_b_post["decision"], "allow")
        self.assertEqual(read_b_post["body"], "Data B")
        svc_reopened.close()


if __name__ == "__main__":
    unittest.main()
