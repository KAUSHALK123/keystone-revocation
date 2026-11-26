"""Tests for authorization policies, ownership, and zero-knowledge denials (AC01 - AC09)."""
from pathlib import Path
import tempfile
import unittest

from quantumvault.core.service import QuantumVaultService


class TestAuthorization(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp_dir.name)
        self.service = QuantumVaultService(state_dir=self.state_dir)
        self.service.setup(
            owners={"doc-1": "alice", "doc-2": "bob"},
            contents={"doc-1": "Alice's Secret Data", "doc-2": "Bob's Public Report"},
            disabled=["eve"],
            key_material="test-key-material-12345"
        )

    def tearDown(self):
        self.service.close()
        self.temp_dir.cleanup()

    def test_ac01_correct_owner_allowed(self):
        """AC01: Correct owner receives allow with exact content body."""
        res = self.service.read(actor="alice", asset="doc-1", request_id="r1")
        self.assertEqual(res["decision"], "allow")
        self.assertEqual(res["body"], "Alice's Secret Data")

    def test_ac02_wrong_owner_denied(self):
        """AC02: Wrong owner is denied access without body disclosure."""
        res = self.service.read(actor="bob", asset="doc-1", request_id="r2")
        self.assertEqual(res["decision"], "deny")
        self.assertNotIn("body", res)

    def test_ac03_unknown_actor_denied(self):
        """AC03: Unknown actor is denied cleanly."""
        res = self.service.read(actor="charlie", asset="doc-1", request_id="r3")
        self.assertEqual(res["decision"], "deny")
        self.assertNotIn("body", res)

    def test_ac04_unknown_resource_denied(self):
        """AC04: Access to non-existent asset is denied cleanly."""
        res = self.service.read(actor="alice", asset="doc-999", request_id="r4")
        self.assertEqual(res["decision"], "deny")
        self.assertNotIn("body", res)

    def test_ac05_disabled_actor_denied(self):
        """AC05: Pre-disabled actor cannot read any resource."""
        res = self.service.read(actor="eve", asset="doc-1", request_id="r5")
        self.assertEqual(res["decision"], "deny")
        self.assertNotIn("body", res)

    def test_ac06_revoked_actor_denied(self):
        """AC06: Actor revoked post-setup is denied subsequent reads."""
        self.service.revoke("alice")
        res = self.service.read(actor="alice", asset="doc-1", request_id="r6")
        self.assertEqual(res["decision"], "deny")
        self.assertNotIn("body", res)

    def test_ac07_unaffected_owner_retains_access(self):
        """AC07: Revoking one actor leaves other authorized actors unaffected."""
        self.service.revoke("alice")
        res = self.service.read(actor="bob", asset="doc-2", request_id="r7")
        self.assertEqual(res["decision"], "allow")
        self.assertEqual(res["body"], "Bob's Public Report")

    def test_ac08_case_sensitive_identifiers(self):
        """AC08: Identifiers are strictly case-sensitive."""
        res = self.service.read(actor="Alice", asset="doc-1", request_id="r8")
        self.assertEqual(res["decision"], "deny")

    def test_ac09_denied_responses_have_no_nested_leaks(self):
        """AC09: Denied response contains no body or sensitive substring."""
        res = self.service.read(actor="eve", asset="doc-1", request_id="r9")
        self.assertEqual(res, {"decision": "deny"})


if __name__ == "__main__":
    unittest.main()
