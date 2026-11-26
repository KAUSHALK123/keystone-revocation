"""Group 8: Identity Edge Cases and Authorization Bypass Tests."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests_round2.helpers import open_service


class TestIdentityEdgeCases(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp_dir.name)
        with open_service(state_dir=self.state_dir) as service:
            service.setup(
                owners={"doc-alice": "alice", "doc-bob": "bob"},
                contents={"doc-alice": "Alice Secret", "doc-bob": "Bob Secret"},
                disabled=[],
                key_material="identity-testing-secret-key"
            )

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_id01_case_sensitivity_and_revocation(self):
        """If 'alice' is revoked, variants ('Alice', 'ALICE') must NOT access 'alice' resources."""
        with open_service(state_dir=self.state_dir) as svc:
            svc.revoke("alice")
            
            # Direct read as 'alice' is denied
            res1 = svc.read("alice", "doc-alice", "r01")
            self.assertEqual(res1["decision"], "deny")

            # Read as 'Alice' attempting to read 'doc-alice' (owned by 'alice')
            # 'Alice' does not own 'doc-alice', so must be denied
            res_upper = svc.read("Alice", "doc-alice", "r02")
            self.assertEqual(res_upper["decision"], "deny", "CRITICAL: Case variation bypassed authorization!")

            res_allcaps = svc.read("ALICE", "doc-alice", "r03")
            self.assertEqual(res_allcaps["decision"], "deny", "CRITICAL: Uppercase variation bypassed authorization!")

    def test_id02_unicode_homoglyphs(self):
        """Cyrillic homoglyph lookalikes cannot access Latin-named resources."""
        cyrillic_alice = "\u0430lice"  # Cyrillic small 'а'
        with open_service(state_dir=self.state_dir) as svc:
            res = svc.read(cyrillic_alice, "doc-alice", "r04")
            self.assertEqual(res["decision"], "deny", "CRITICAL: Unicode homoglyph bypassed authorization!")

    def test_id03_trailing_and_leading_whitespace(self):
        """Trailing and leading whitespace cannot impersonate identity."""
        with open_service(state_dir=self.state_dir) as svc:
            res_trail = svc.read("alice ", "doc-alice", "r05")
            self.assertEqual(res_trail["decision"], "deny")

            res_lead = svc.read(" alice", "doc-alice", "r06")
            self.assertEqual(res_lead["decision"], "deny")

    def test_id04_null_bytes_in_identity(self):
        """Null bytes in identity strings do not allow prefix matching or bypass."""
        with open_service(state_dir=self.state_dir) as svc:
            res_null = svc.read("alice\x00admin", "doc-alice", "r07")
            self.assertEqual(res_null["decision"], "deny")

    def test_id05_idor_confused_deputy(self):
        """User A attempting to read User B's resource is strictly denied."""
        with open_service(state_dir=self.state_dir) as svc:
            idor = svc.read("alice", "doc-bob", "r08")
            self.assertEqual(idor["decision"], "deny", "CRITICAL: IDOR vulnerability! Alice read Bob's resource.")

    def test_id06_empty_and_none_identities(self):
        """Empty or None identity fields fail closed."""
        with open_service(state_dir=self.state_dir) as svc:
            empty = svc.read("", "doc-alice", "r09")
            self.assertEqual(empty["decision"], "deny")

            blank = svc.read("   ", "doc-alice", "r10")
            self.assertEqual(blank["decision"], "deny")


if __name__ == "__main__":
    unittest.main()
