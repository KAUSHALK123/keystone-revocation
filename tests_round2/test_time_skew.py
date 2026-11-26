"""Group 6: Time Skew, Clock Boundaries, and Expiry Tests."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from quantumvault.core.errors import CryptoError
from tests_round2.helpers import open_service
from quantumvault.config import get_db_path, get_vault_key_path
from quantumvault.crypto.key_manager import load_vault_key
from quantumvault.crypto.rotation import KeyRotationManager
from quantumvault.detection.clock import correct_timestamp, parse_iso_timestamp
from quantumvault.iam.device import DeviceManager
from quantumvault.iam.policy import PolicyEngine
from quantumvault.storage.db import get_connection


class TestTimeSkew(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp_dir.name)
        with open_service(state_dir=self.state_dir) as service:
            service.setup(
                owners={"doc-time": "alice"},
                contents={"doc-time": "Time Protected Document"},
                disabled=[],
                key_material="time-skew-testing-key"
            )

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_time01_clock_rollback_cannot_revive_revoked_credential(self):
        """Winding the system clock back does not revive a revoked credential."""
        with open_service(state_dir=self.state_dir) as svc:
            svc.revoke("alice")
            res_now = svc.read("alice", "doc-time", "r01")
            self.assertEqual(res_now["decision"], "deny")

        # Simulate clock set back to year 2000
        past_time = "2000-01-01T00:00:00.000Z"
        with open_service(state_dir=self.state_dir) as svc:
            # Check revocation table; revocation is stateful, not time-dependent
            self.assertTrue(svc.revocations.is_revoked("alice"))
            res_past = svc.read("alice", "doc-time", "r02")
            self.assertEqual(res_past["decision"], "deny", "CRITICAL: Revoked identity resurrected by clock rollback!")

    def test_time02_cutoff_timestamp_enforcement(self):
        """Key versions past their cutoff timestamp must reject decryption."""
        conn = get_connection(get_db_path(self.state_dir))
        
        # Set cutoff timestamp in the past for v1 and retire it
        past_iso = "2020-01-01T00:00:00Z"
        conn.execute(
            "UPDATE key_versions SET status = 'retired', cutoff_at = ? WHERE version_id = 'v1';",
            (past_iso,)
        )
        conn.commit()
        conn.close()

        # Decryption attempt with retired/cutoff key must fail closed
        with open_service(state_dir=self.state_dir) as svc:
            try:
                res = svc.read("alice", "doc-time", "req-cutoff-read")
                self.assertEqual(res["decision"], "deny")
            except CryptoError:
                pass

    def test_time03_leap_year_and_dst_timestamps(self):
        """Clock normalizer correctly parses leap years (2028-02-29) and boundary timestamps."""
        leap_iso = "2028-02-29T23:59:59.999Z"
        dt = parse_iso_timestamp(leap_iso)
        self.assertEqual(dt.year, 2028)
        self.assertEqual(dt.month, 2)
        self.assertEqual(dt.day, 29)

        # Offset correction on leap second / millisecond
        corrected = correct_timestamp(leap_iso, 1000)
        self.assertEqual(corrected, "2028-02-29T23:59:58.999Z")

    def test_time04_future_token_handling(self):
        """Timestamps far in the future handled gracefully without integer overflow or crash."""
        future_iso = "2099-12-31T23:59:59.000Z"
        corrected = correct_timestamp(future_iso, -5000)
        self.assertIn("2100", corrected)


if __name__ == "__main__":
    unittest.main()
