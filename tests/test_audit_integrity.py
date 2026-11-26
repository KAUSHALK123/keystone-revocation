"""Tests for cryptographic audit hash chaining, checkpoints, and tamper detection (AUD01 - AUD12)."""
from pathlib import Path
import tempfile
import unittest

from quantumvault.audit.checkpoints import CheckpointManager
from quantumvault.audit.logger import GENESIS_PREV_HASH, AuditLogger
from quantumvault.audit.verifier import AuditLogVerifier
from quantumvault.core.service import QuantumVaultService
from quantumvault.storage.db import get_connection, transaction


class TestAuditIntegrity(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp_dir.name)

        self.service = QuantumVaultService(state_dir=self.state_dir)
        self.service.setup(
            owners={"file-1": "analyst-1"},
            contents={"file-1": "Q3 Financials"},
            disabled=[],
            key_material="audit-integrity-test-key"
        )

        # Generate a small chain of access events
        self.service.read("analyst-1", "file-1", "req-1")
        self.service.read("intruder", "file-1", "req-2")
        self.service.read("analyst-1", "file-1", "req-3")

        self.conn = get_connection(self.service.db_path)
        self.verifier = AuditLogVerifier(self.conn)
        self.chk_mgr = CheckpointManager(self.conn)

    def tearDown(self):
        self.conn.close()
        self.service.close()
        self.temp_dir.cleanup()

    def test_aud01_events_link_via_hash_chain(self):
        """AUD01: Successive audit rows link prev_hash to preceding entry_hash."""
        chain = self.service.audit_logger.get_chain()
        self.assertGreaterEqual(len(chain), 3)

        for i in range(1, len(chain)):
            self.assertEqual(
                chain[i]["prev_hash"],
                chain[i - 1]["entry_hash"],
                f"Row {i} prev_hash does not match Row {i-1} entry_hash"
            )

    def test_aud02_first_event_links_to_genesis_hash(self):
        """AUD02: The first audit row prev_hash is the 64-character genesis zero-hash."""
        chain = self.service.audit_logger.get_chain()
        self.assertEqual(chain[0]["prev_hash"], GENESIS_PREV_HASH)

    def test_aud03_monotonic_sequence_numbers(self):
        """AUD03: Sequence numbers increment strictly by 1 (1, 2, 3, ...)."""
        chain = self.service.audit_logger.get_chain()
        for idx, row in enumerate(chain):
            self.assertEqual(row["sequence_num"], idx + 1)

    def test_aud04_unmodified_log_verifies_valid(self):
        """AUD04: Verifier tool reports 'valid' on pristine audit log."""
        report = self.verifier.verify()
        self.assertEqual(report["status"], "valid")
        self.assertEqual(report["verified_records"], len(self.service.audit_logger.get_chain()))
        self.assertIsNone(report["first_inconsistency"])

    def test_aud05_detection_of_modified_decision(self):
        """AUD05: Flipped decision (e.g. deny changed to allow) is detected as hash_mismatch."""
        # Maliciously flip req-2 decision in the database
        with transaction(self.conn):
            self.conn.execute("UPDATE audit_events SET decision = 'allow' WHERE request_id = 'req-2';")

        report = self.verifier.verify()
        self.assertEqual(report["status"], "tampered")
        self.assertIsNotNone(report["first_inconsistency"])
        self.assertEqual(report["first_inconsistency"]["error_type"], "hash_mismatch")
        self.assertEqual(report["first_inconsistency"]["request_id"], "req-2")

    def test_aud06_detection_of_modified_actor_or_asset(self):
        """AUD06: Modifying actor_id or asset_id triggers hash mismatch detection."""
        with transaction(self.conn):
            self.conn.execute("UPDATE audit_events SET actor_id = 'admin' WHERE request_id = 'req-1';")

        report = self.verifier.verify()
        self.assertEqual(report["status"], "tampered")
        self.assertEqual(report["first_inconsistency"]["error_type"], "hash_mismatch")

    def test_aud07_detection_of_modified_timestamp(self):
        """AUD07: Forging an event timestamp is detected by the verifier."""
        with transaction(self.conn):
            self.conn.execute("UPDATE audit_events SET event_time_utc = '1970-01-01T00:00:00Z' WHERE request_id = 'req-1';")

        report = self.verifier.verify()
        self.assertEqual(report["status"], "tampered")
        self.assertEqual(report["first_inconsistency"]["error_type"], "hash_mismatch")

    def test_aud08_detection_of_deleted_intermediate_entry(self):
        """AUD08: Deleting an intermediate log row breaks the hash chain."""
        with transaction(self.conn):
            self.conn.execute("DELETE FROM audit_events WHERE request_id = 'req-2';")

        report = self.verifier.verify()
        self.assertEqual(report["status"], "tampered")
        # Should detect sequence gap or broken chain
        self.assertIn(report["first_inconsistency"]["error_type"], ("sequence_gap", "broken_chain"))

    def test_aud09_detection_of_injected_phantom_entry(self):
        """AUD09: Injecting an unauthorized row breaks hash chaining."""
        with transaction(self.conn):
            self.conn.execute(
                "INSERT INTO audit_events (request_id, event_time_utc, actor_id, op, asset_id, decision, rule, prev_hash, entry_hash) "
                "VALUES ('phantom-req', '2026-01-01T00:00:00Z', 'hacker', 'read', 'file-1', 'allow', 'owner_allowed', 'fake-prev', 'fake-hash');"
            )

        report = self.verifier.verify()
        self.assertEqual(report["status"], "tampered")

    def test_aud10_signed_checkpoint_commits_to_cumulative_chain(self):
        """AUD10: Creating a signed checkpoint anchors the cumulative chain state."""
        chk = self.chk_mgr.create_checkpoint("chk-test-1")
        self.assertIsNotNone(chk)
        self.assertEqual(chk["sequence_up_to"], 3)
        self.assertTrue(self.chk_mgr.verify_checkpoint(chk))

        report = self.verifier.verify()
        self.assertEqual(report["status"], "valid")
        self.assertEqual(report["checkpoints_verified"], 1)
        self.assertTrue(report["checkpoints_valid"])

    def test_aud11_detection_of_log_truncation(self):
        """AUD11: Truncating the end of the log is detected against external checkpoint."""
        # 1. Establish checkpoint at sequence 3
        self.chk_mgr.create_checkpoint("chk-anchor-3")

        # 2. Attacker deletes the latest row (sequence 3) to hide an event
        with transaction(self.conn):
            self.conn.execute("DELETE FROM audit_events WHERE sequence_num = 3;")

        report = self.verifier.verify()
        self.assertEqual(report["status"], "tampered")
        self.assertEqual(report["first_inconsistency"]["error_type"], "truncated_log")

    def test_aud12_detection_of_tampered_checkpoint_hmac(self):
        """AUD12: Altered checkpoint HMAC signature is detected during verification."""
        self.chk_mgr.create_checkpoint("chk-tamper-hmac")
        with transaction(self.conn):
            self.conn.execute(
                "UPDATE audit_checkpoints SET checkpoint_hmac = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' "
                "WHERE checkpoint_id = 'chk-tamper-hmac';"
            )

        report = self.verifier.verify()
        self.assertEqual(report["status"], "tampered")
        self.assertEqual(report["first_inconsistency"]["error_type"], "invalid_checkpoint_hmac")


if __name__ == "__main__":
    unittest.main()
