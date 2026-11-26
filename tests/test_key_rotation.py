"""Tests for cryptographic key rotation, lifecycle states, grace periods, and asset rewrapping (ROT01 - ROT10)."""
from pathlib import Path
import tempfile
import unittest

from quantumvault.config import get_vault_key_path
from quantumvault.core.errors import CryptoError
from quantumvault.core.service import QuantumVaultService
from quantumvault.crypto.key_manager import load_vault_key
from quantumvault.crypto.rotation import KeyRotationManager
from quantumvault.storage.db import get_connection, init_db
from quantumvault.vault.resources import ResourceVault


class TestKeyRotation(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp_dir.name)

        self.service = QuantumVaultService(state_dir=self.state_dir)
        self.service.setup(
            owners={"file-1": "owner-1", "file-2": "owner-1"},
            contents={"file-1": "Original Content 1", "file-2": "Original Content 2"},
            disabled=[],
            key_material="key-rotation-test-secret-marker"
        )

        self.conn = get_connection(self.service.db_path)
        self.kek = load_vault_key(get_vault_key_path(self.state_dir))
        self.rotation_mgr = KeyRotationManager(self.conn, self.kek)
        self.vault = ResourceVault(self.conn, key_resolver=self.rotation_mgr)

    def tearDown(self):
        self.conn.close()
        self.service.close()
        self.temp_dir.cleanup()

    def test_rot01_setup_initializes_v1_active(self):
        """ROT01: Setup initializes key version v1 in active status."""
        v1 = self.rotation_mgr.key_repo.get_version("v1")
        self.assertIsNotNone(v1)
        self.assertEqual(v1["status"], "active")
        active = self.rotation_mgr.key_repo.get_active_version()
        self.assertEqual(active["version_id"], "v1")

    def test_rot02_rotation_transitions_v1_to_grace_and_v2_to_active(self):
        """ROT02: Rotation transitions V1 to grace_period and V2 to active."""
        res = self.rotation_mgr.rotate_key("v2", grace_seconds=60.0, rewrap_assets=False)
        self.assertEqual(res["previous_version"], "v1")
        self.assertEqual(res["active_version"], "v2")

        v1 = self.rotation_mgr.key_repo.get_version("v1")
        v2 = self.rotation_mgr.key_repo.get_version("v2")
        self.assertEqual(v1["status"], "grace_period")
        self.assertIsNotNone(v1["cutoff_at"])
        self.assertEqual(v2["status"], "active")

    def test_rot03_reads_succeed_during_grace_period(self):
        """ROT03: Assets on V1 can still be decrypted during V1's grace period."""
        # Rotate to v2 without rewrapping so asset remains on v1
        self.rotation_mgr.rotate_key("v2", grace_seconds=60.0, rewrap_assets=False)

        owner, body = self.vault.retrieve_resource("file-1")
        self.assertEqual(owner, "owner-1")
        self.assertEqual(body, "Original Content 1")

    def test_rot04_asset_rewrapping_reencrypts_ciphertext(self):
        """ROT04: Re-wrapping changes the stored ciphertext and nonce in SQLite."""
        raw_pre = self.vault.repo.get("file-1")
        old_ciphertext = raw_pre["encrypted_body"]
        old_nonce = raw_pre["nonce"]

        # Rotate and rewrap
        res = self.rotation_mgr.rotate_key("v2", grace_seconds=60.0, rewrap_assets=True)
        self.assertEqual(res["rewrapped_count"], 2)

        raw_post = self.vault.repo.get("file-1")
        self.assertNotEqual(raw_post["encrypted_body"], old_ciphertext)
        self.assertNotEqual(raw_post["nonce"], old_nonce)
        self.assertEqual(raw_post["key_version"], "v2")

    def test_rot05_rewrapped_asset_decrypts_cleanly(self):
        """ROT05: Rewrapped asset decrypts to exact original content under new key."""
        self.rotation_mgr.rotate_key("v2", grace_seconds=60.0, rewrap_assets=True)
        owner, body = self.vault.retrieve_resource("file-1")
        self.assertEqual(owner, "owner-1")
        self.assertEqual(body, "Original Content 1")

    def test_rot06_expired_cutoff_transitions_to_retired(self):
        """ROT06: Key past its cutoff timestamp is transitioned to retired."""
        self.rotation_mgr.rotate_key("v2", grace_seconds=1.0, rewrap_assets=False)
        self.rotation_mgr.expire_cutoff("v1")

        v1 = self.rotation_mgr.key_repo.get_version("v1")
        self.assertEqual(v1["status"], "retired")

    def test_rot07_retired_key_decryption_rejected(self):
        """ROT07: Decryption attempt using a retired key is strictly rejected."""
        self.rotation_mgr.rotate_key("v2", grace_seconds=1.0, rewrap_assets=False)
        self.rotation_mgr.expire_cutoff("v1")

        with self.assertRaises(CryptoError):
            self.vault.retrieve_resource("file-1")

    def test_rot08_new_encryptions_use_active_version(self):
        """ROT08: Newly stored resources use the newly active key version."""
        self.rotation_mgr.rotate_key("v2", grace_seconds=60.0, rewrap_assets=True)
        self.vault.store_resource("file-3", "owner-1", "New Content Under V2", key_version="v2")

        rec = self.vault.repo.get("file-3")
        self.assertEqual(rec["key_version"], "v2")
        _, body = self.vault.retrieve_resource("file-3")
        self.assertEqual(body, "New Content Under V2")

    def test_rot09_multi_step_rotation_integrity(self):
        """ROT09: Sequential rotations (V1 -> V2 -> V3) maintain key lifecycle integrity."""
        self.rotation_mgr.rotate_key("v2", grace_seconds=60.0, rewrap_assets=True)
        self.rotation_mgr.rotate_key("v3", grace_seconds=60.0, rewrap_assets=True)

        v3 = self.rotation_mgr.key_repo.get_version("v3")
        self.assertEqual(v3["status"], "active")
        v2 = self.rotation_mgr.key_repo.get_version("v2")
        self.assertEqual(v2["status"], "grace_period")

        _, body1 = self.vault.retrieve_resource("file-1")
        self.assertEqual(body1, "Original Content 1")

    def test_rot10_interrupted_rotation_recovery(self):
        """ROT10: Interrupted rotation state is recovered durably."""
        # Simulate interruption during rotation to v2
        self.rotation_mgr.app_state.set("key_rotation_status", "in_progress:v1->v2")
        # Ensure v2 key exists
        v2_raw = self.rotation_mgr.initialize_initial_version("v2")

        rec_res = self.rotation_mgr.recover_interrupted_rotation()
        self.assertIsNotNone(rec_res)
        self.assertEqual(rec_res["status"], "recovered")
        self.assertEqual(self.rotation_mgr.app_state.get("key_rotation_status"), "completed:v2")
        self.assertEqual(self.rotation_mgr.app_state.get("active_key_version"), "v2")


if __name__ == "__main__":
    unittest.main()
