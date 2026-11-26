"""Tests for multi-role authorization, least-privilege enforcement, and device-level policy (PER01 - PER08)."""
from pathlib import Path
import tempfile
import unittest

from quantumvault.iam.device import DeviceManager
from quantumvault.iam.policy import ROLE_HIERARCHY, PolicyEngine
from quantumvault.storage.db import get_connection, init_db, transaction
from quantumvault.storage.repositories import IdentityRepository


class TestPermissions(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.conn = get_connection(self.db_path)
        init_db(self.conn)

        self.identities = IdentityRepository(self.conn)
        self.device_mgr = DeviceManager(self.conn)

        with transaction(self.conn):
            self.identities.upsert("viewer-alice", status="active", role="viewer")
            self.identities.upsert("analyst-bob", status="active", role="analyst")
            self.identities.upsert("auditor-carol", status="active", role="auditor")
            self.identities.upsert("admin-dave", status="active", role="admin")

    def tearDown(self):
        self.conn.close()
        self.temp_dir.cleanup()

    def test_per01_role_hierarchy_ordering(self):
        """PER01: Role hierarchy levels are ordered correctly."""
        self.assertLess(ROLE_HIERARCHY["viewer"], ROLE_HIERARCHY["analyst"])
        self.assertLess(ROLE_HIERARCHY["analyst"], ROLE_HIERARCHY["auditor"])
        self.assertLess(ROLE_HIERARCHY["auditor"], ROLE_HIERARCHY["admin"])

    def test_per02_least_privilege_viewer_cannot_admin(self):
        """PER02: Least privilege: viewer role cannot perform administrative operations."""
        dec, rule = PolicyEngine.evaluate_access(
            actor="viewer-alice",
            asset="asset-1",
            asset_owner="viewer-alice",
            is_disabled=False,
            role="viewer",
            required_role="admin"
        )
        self.assertEqual(dec, "deny")
        self.assertEqual(rule, "insufficient_privilege")

    def test_per03_admin_cannot_read_unauthorized_user_asset(self):
        """PER03: Least privilege: admin cannot read an asset owned by another user without authorization."""
        dec, rule = PolicyEngine.evaluate_access(
            actor="admin-dave",
            asset="secret-report",
            asset_owner="viewer-alice",
            is_disabled=False,
            role="admin"
        )
        self.assertEqual(dec, "deny")
        self.assertEqual(rule, "owner_required")

    def test_per04_auditor_authorized_for_audit_tier(self):
        """PER04: Auditor is authorized for auditor-tier operations."""
        dec, rule = PolicyEngine.evaluate_access(
            actor="auditor-carol",
            asset="audit-trail",
            asset_owner="auditor-carol",
            is_disabled=False,
            role="auditor",
            required_role="auditor"
        )
        self.assertEqual(dec, "allow")
        self.assertEqual(rule, "owner_allowed")

    def test_per05_device_level_policy_revoked_device_denied(self):
        """PER05: Active actor presenting a revoked device is denied access."""
        dec, rule = PolicyEngine.evaluate_access(
            actor="viewer-alice",
            asset="alice-file",
            asset_owner="viewer-alice",
            is_disabled=False,
            device_id="dev-alice-compromised",
            is_device_revoked=True
        )
        self.assertEqual(dec, "deny")
        self.assertEqual(rule, "device_revoked")

    def test_per06_device_level_policy_active_device_allowed(self):
        """PER06: Active actor presenting an active device is allowed access."""
        dec, rule = PolicyEngine.evaluate_access(
            actor="viewer-alice",
            asset="alice-file",
            asset_owner="viewer-alice",
            is_disabled=False,
            device_id="dev-alice-good",
            is_device_revoked=False
        )
        self.assertEqual(dec, "allow")
        self.assertEqual(rule, "owner_allowed")

    def test_per07_disabled_actor_revokes_all_devices(self):
        """PER07: When actor is disabled, access is denied even if device is active."""
        dec, rule = PolicyEngine.evaluate_access(
            actor="viewer-alice",
            asset="alice-file",
            asset_owner="viewer-alice",
            is_disabled=True,
            device_id="dev-alice-good",
            is_device_revoked=False
        )
        self.assertEqual(dec, "deny")
        self.assertEqual(rule, "identity_disabled")

    def test_per08_analyst_cannot_execute_admin_tasks(self):
        """PER08: Analyst cannot execute admin tasks without proper privilege."""
        dec, rule = PolicyEngine.evaluate_access(
            actor="analyst-bob",
            asset="admin-key-vault",
            asset_owner="analyst-bob",
            is_disabled=False,
            role="analyst",
            required_role="admin"
        )
        self.assertEqual(dec, "deny")
        self.assertEqual(rule, "insufficient_privilege")


if __name__ == "__main__":
    unittest.main()
