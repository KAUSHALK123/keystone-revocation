"""Tests for structured audit logging and decision correlation (AU01 - AU07)."""
from pathlib import Path
import tempfile
import unittest

from quantumvault.audit.logger import AuditLogger
from quantumvault.core.service import QuantumVaultService
from quantumvault.storage.db import get_connection, init_db


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp_dir.name)
        self.service = QuantumVaultService(state_dir=self.state_dir)
        self.service.setup(
            owners={"report-1": "analyst-1"},
            contents={"report-1": "Q3 Financials"},
            disabled=[],
            key_material="audit-test-marker"
        )

    def tearDown(self):
        self.service.close()
        self.temp_dir.cleanup()

    def test_au01_authorized_read_records_allow(self):
        """AU01: Allowed read records exact allow decision against request ID."""
        self.service.read(actor="analyst-1", asset="report-1", request_id="req-allow-1")
        audit_res = self.service.audit(request_id="req-allow-1")
        self.assertEqual(audit_res["request_id"], "req-allow-1")
        self.assertEqual(audit_res["decision"], "allow")

    def test_au02_denied_read_records_deny(self):
        """AU02: Denied read records exact deny decision against request ID."""
        self.service.read(actor="intruder", asset="report-1", request_id="req-deny-1")
        audit_res = self.service.audit(request_id="req-deny-1")
        self.assertEqual(audit_res["request_id"], "req-deny-1")
        self.assertEqual(audit_res["decision"], "deny")

    def test_au03_historical_audit_unchanged_by_subsequent_revocation(self):
        """AU03: Subsequent actor revocation does not rewrite past allowed audit records."""
        # 1. Analyst performs authorized read
        self.service.read(actor="analyst-1", asset="report-1", request_id="req-past-1")
        
        # 2. Analyst is subsequently revoked
        self.service.revoke("analyst-1")
        
        # 3. New read is denied
        self.service.read(actor="analyst-1", asset="report-1", request_id="req-new-1")
        
        # 4. Audit query for past read MUST still report 'allow'
        past_audit = self.service.audit(request_id="req-past-1")
        self.assertEqual(past_audit["decision"], "allow")
        
        # 5. Audit query for new read reports 'deny'
        new_audit = self.service.audit(request_id="req-new-1")
        self.assertEqual(new_audit["decision"], "deny")

    def test_au04_conflicting_request_id_cannot_overwrite_history(self):
        """AU04: Submitting an identical request ID later does not overwrite recorded decision."""
        # Record initial allow
        self.service.read(actor="analyst-1", asset="report-1", request_id="req-fixed-1")
        self.assertEqual(self.service.audit("req-fixed-1")["decision"], "allow")

        # Now revoke and attempt to reuse same request ID with a denied read
        self.service.revoke("analyst-1")
        self.service.read(actor="analyst-1", asset="report-1", request_id="req-fixed-1")

        # Decision in audit store must preserve the original 'allow'
        self.assertEqual(self.service.audit("req-fixed-1")["decision"], "allow")

    def test_au06_user_newlines_do_not_inject_log_records(self):
        """AU06: User text with newlines does not create phantom audit rows."""
        malicious_id = "req-1\nFAKE_EVENT|2026-01-01|admin|allow"
        self.service.read(actor="analyst-1", asset="report-1", request_id=malicious_id)

        # Count rows in audit_events table
        cursor = self.service.conn.execute("SELECT count(*) as cnt FROM audit_events;")
        row_count = cursor.fetchone()["cnt"]
        self.assertEqual(row_count, 1)


if __name__ == "__main__":
    unittest.main()
