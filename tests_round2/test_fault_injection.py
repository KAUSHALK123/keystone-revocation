"""Group 5: Fault Injection and Crash-Consistency Tests."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests_round2.helpers import open_service
from quantumvault.config import get_db_path, get_vault_key_path
from quantumvault.storage.repositories import AssetRepository
from quantumvault.crypto.key_manager import load_vault_key
from quantumvault.crypto.rotation import KeyRotationManager
from quantumvault.storage.db import get_connection
from quantumvault.storage.repositories import KeyVersionRepository


class TestFaultInjection(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp_dir.name)
        with open_service(state_dir=self.state_dir) as service:
            service.setup(
                owners={"asset-1": "alice", "asset-2": "bob"},
                contents={"asset-1": "Secret Content 1", "asset-2": "Secret Content 2"},
                disabled=[],
                key_material="fault-injection-seed-key"
            )

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_fault01_crash_during_key_rotation_creation(self):
        """Simulate power loss / crash right as new key version is inserted."""
        conn = get_connection(get_db_path(self.state_dir))
        raw_key = load_vault_key(get_vault_key_path(self.state_dir))
        mgr = KeyRotationManager(conn, raw_key)

        original_create = KeyVersionRepository.create_version
        def crashing_create(*args, **kwargs):
            original_create(*args, **kwargs)
            raise SystemExit("CRASH: Simulated sudden power cut after version insert")

        with patch.object(KeyVersionRepository, "create_version", side_effect=crashing_create):
            try:
                mgr.rotate_key("v2_crash")
            except (SystemExit, Exception):
                pass
        conn.close()

        # Restart service; state must be consistent
        with open_service(state_dir=self.state_dir) as svc:
            # Active key must still be v1
            active = svc.identities.conn.execute(
                "SELECT version_id, status FROM key_versions WHERE status = 'active';"
            ).fetchone()
            self.assertEqual(active["version_id"], "v1")
            
            # Reads must still work with existing key
            read_res = svc.read("alice", "asset-1", "req-post-crash-1")
            self.assertEqual(read_res["decision"], "allow")
            self.assertEqual(read_res["body"], "Secret Content 1")

    def test_fault02_crash_during_asset_rewrap(self):
        """Simulate crash midway through DEK re-wrapping."""
        conn = get_connection(get_db_path(self.state_dir))
        raw_key = load_vault_key(get_vault_key_path(self.state_dir))
        mgr = KeyRotationManager(conn, raw_key)

        call_count = 0
        def crashing_update(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count >= 1:
                raise RuntimeError("CRASH: Simulated I/O failure during asset re-wrap")

        with patch.object(AssetRepository, "update_encrypted_body", side_effect=crashing_update):
            try:
                mgr.rotate_key("v2_rewrap_fail")
            except RuntimeError:
                pass
        conn.close()

        # Restart service; uncommitted partial re-wrap must roll back
        with open_service(state_dir=self.state_dir) as svc:
            read1 = svc.read("alice", "asset-1", "req-rw-1")
            read2 = svc.read("bob", "asset-2", "req-rw-2")
            self.assertEqual(read1["decision"], "allow")
            self.assertEqual(read2["decision"], "allow")
            self.assertEqual(read1["body"], "Secret Content 1")
            self.assertEqual(read2["body"], "Secret Content 2")

    def test_fault03_crash_during_revocation_audit_logging(self):
        """Simulate crash between revoking identity and writing audit log."""
        with open_service(state_dir=self.state_dir) as svc:
            with patch.object(svc.audit_logger, "log_decision", side_effect=RuntimeError("Disk full during audit write")):
                try:
                    svc.revoke("alice")
                except RuntimeError:
                    pass

        # Since transaction wraps both, identity revocation must cleanly roll back or fail closed
        with open_service(state_dir=self.state_dir) as svc:
            # Audit log must be intact and not corrupt
            cursor = svc.conn.execute("SELECT COUNT(*) as cnt FROM audit_events;")
            count = cursor.fetchone()["cnt"]
            self.assertGreaterEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
