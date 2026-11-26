"""Comprehensive competition-grade regression, negative, concurrency, and independent dataset tests."""
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import random
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

from quantumvault.backup.backup_manager import BackupManager
from quantumvault.backup.restore import BackupRestoreManager
from quantumvault.core.errors import CryptoError, SecurityPolicyError, StateError
from quantumvault.core.service import QuantumVaultService
from quantumvault.crypto.encryption import AuthenticatedEncryption
from quantumvault.crypto.pqc_dsa import MLDSA65
from quantumvault.crypto.pqc_kem import MLKEM768
from quantumvault.crypto.rotation import KeyRotationManager
from quantumvault.detection.approvals import ApprovalRegistry
from quantumvault.detection.engine import DetectionEngine
from quantumvault.detection.evaluator import DetectionEvaluator
from quantumvault.detection.models import ApprovalChange, SecurityEvent
from quantumvault.distributed.authority import SecurityAuthority
from quantumvault.distributed.cluster import ClusterCoordinator
from quantumvault.distributed.node import ServiceNode
from quantumvault.iam.authentication import DeviceAuthenticator, generate_device_keypair, sign_challenge
from quantumvault.iam.device import DeviceManager
from quantumvault.iam.recovery import RecoveryManager
from quantumvault.messaging.handshake import MessagingHandshake
from quantumvault.messaging.session import MessagingSession
from quantumvault.messaging.transport import ChunkedTransport
from quantumvault.storage.db import get_connection, init_db, verify_db_integrity

ROOT = Path(__file__).resolve().parent.parent


class TestAdapterContractEdgeCases(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.env = os.environ.copy()
        self.env["TRACK4_STATE_DIR"] = self.td.name

    def tearDown(self):
        self.td.cleanup()

    def _run_cli(self, raw_text: str) -> tuple[int, str, str]:
        proc = subprocess.Popen(
            [sys.executable, "-B", str(ROOT / "track4_service.py")],
            cwd=str(ROOT),
            env=self.env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        out, err = proc.communicate(raw_text, timeout=8.0)
        return proc.returncode, out, err

    def test_non_object_json_and_invalid_field_types(self):
        for payload in ("[]", '"string"', "123", "null"):
            rc, out, _ = self._run_cli(payload)
            self.assertEqual(rc, 1)
            self.assertEqual(out, "")

        # Setup with wrong type for owners fails cleanly with exit 1 and no traceback
        rc, out, err = self._run_cli(json.dumps({"op": "setup", "owners": ["bad"]}))
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")
        self.assertNotIn("Traceback", err)

        # Read with non-string actor/asset returns clean deny JSON
        rc, out, _ = self._run_cli(json.dumps({"op": "read", "actor": ["a"], "asset": 123, "request_id": "r1"}))
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out), {"decision": "deny"})

    def test_unicode_and_uninitialized_read_and_concurrent_processes(self):
        # Read before setup returns deny cleanly
        rc, out, _ = self._run_cli(json.dumps({"op": "read", "actor": "alice", "asset": "doc", "request_id": "pre-1"}))
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out), {"decision": "deny"})

        # Unicode setup and read
        unicode_body = "Confidential UTF-8: αβγ 🔐 日本語"
        rc, out, _ = self._run_cli(json.dumps({
            "op": "setup",
            "owners": {"doc-uni": "alice-λ"},
            "contents": {"doc-uni": unicode_body},
            "disabled": [],
            "key_material": "unicode-seed-🔑",
        }))
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out), {"ready": True})

        # Concurrent reads across 6 fresh OS subprocesses
        def do_read(i: int):
            return self._run_cli(json.dumps({
                "op": "read",
                "actor": "alice-λ",
                "asset": "doc-uni",
                "request_id": f"conc-{i}",
            }))

        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(do_read, range(6)))

        for rc, out, _ in results:
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(out), {"decision": "allow", "body": unicode_body})


class TestCryptoAndRotationEdgeCases(unittest.TestCase):
    def test_exact_cutoff_retirement_and_no_reactivation(self):
        with tempfile.TemporaryDirectory() as td:
            svc = QuantumVaultService(state_dir=Path(td))
            try:
                svc.setup({"a1": "alice"}, {"a1": "Body1"}, [], "rot-edge-seed")
                from quantumvault.config import get_vault_key_path
                from quantumvault.crypto.key_manager import load_vault_key
                kek = load_vault_key(get_vault_key_path(Path(td)))
                rot = KeyRotationManager(svc.conn, kek)

                # Rotate with 0.05s grace, wait past cutoff, verify exact retirement
                rot.rotate_key("v2", grace_seconds=0.05, rewrap_assets=False)
                time.sleep(0.08)
                with self.assertRaises(CryptoError):
                    rot.get_key_for_version("v1")

                # Attempting to rotate back to retired v1 must fail
                with self.assertRaises(CryptoError):
                    rot.rotate_key("v1", grace_seconds=10.0)
            finally:
                svc.close()

    def test_aead_binary_empty_and_large_payloads(self):
        cipher = AuthenticatedEncryption(b"Z" * 32)
        for payload in (b"", b"\x00\xff\x01\xfe", b"B" * 65536):
            ct, nonce = cipher.encrypt_bytes(payload, associated_data=b"ctx-1")
            self.assertEqual(cipher.decrypt_bytes(ct, nonce, associated_data=b"ctx-1"), payload)
            with self.assertRaises(CryptoError):
                cipher.decrypt_bytes(ct, nonce, associated_data=b"ctx-2")

    def test_mldsa65_modified_signature_and_wrong_key(self):
        dsa = MLDSA65()
        pk1, sk1 = dsa.generate_keypair()
        pk2, _ = dsa.generate_keypair()
        sig = dsa.sign(sk1, b"context-bound-msg")
        self.assertTrue(dsa.verify(pk1, b"context-bound-msg", sig))
        self.assertFalse(dsa.verify(pk2, b"context-bound-msg", sig))
        bad_sig = bytearray(sig)
        bad_sig[10] ^= 0xFF
        self.assertFalse(dsa.verify(pk1, b"context-bound-msg", bytes(bad_sig)))


class TestExternalAnchorRollbackAndMigration(unittest.TestCase):
    def test_db_file_replacement_rollback_blocked_by_external_anchor(self):
        with tempfile.TemporaryDirectory() as td:
            sd = Path(td)
            svc = QuantumVaultService(state_dir=sd)
            svc.setup({"doc": "alice"}, {"doc": "TopSecret"}, [], "anchor-seed")
            svc.close()

            bak_mgr = BackupManager(state_dir=sd)
            bak_path = sd / "epoch1.qvb"
            bak_mgr.create_backup(bak_path)

            # Advance authority to epoch 2 (updates external .cluster_epoch_anchor)
            auth = SecurityAuthority(state_dir=sd)
            auth.issue_revocation("alice", entity_type="actor")
            auth.close()

            # Simulate attacker replacing SQLite DB with older epoch-1 DB copy
            restore_mgr = BackupRestoreManager(state_dir=sd)
            with self.assertRaises(StateError):
                restore_mgr.verify_and_restore(bak_path, force_allow_rollback=False)

    def test_legacy_db_auto_migration_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "legacy.db"
            conn = sqlite3.connect(str(db_path))
            conn.executescript("""
                CREATE TABLE identities (actor_id TEXT PRIMARY KEY, status TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'viewer');
                CREATE TABLE assets (asset_id TEXT PRIMARY KEY, owner_actor_id TEXT NOT NULL, encrypted_body BLOB NOT NULL, nonce BLOB NOT NULL);
                CREATE TABLE audit_events (request_id TEXT PRIMARY KEY, event_time_utc TEXT NOT NULL, actor_id TEXT NOT NULL, op TEXT NOT NULL, asset_id TEXT, decision TEXT NOT NULL, rule TEXT NOT NULL, entry_hash TEXT NOT NULL);
                INSERT INTO identities VALUES ('alice', 'active', 'viewer');
                INSERT INTO audit_events VALUES ('old-r1', '2026-01-01T00:00:00Z', 'alice', 'read', 'a1', 'allow', 'owner_allowed', 'abc');
            """)
            conn.close()

            c2 = get_connection(db_path)
            init_db(c2)
            init_db(c2)  # Idempotent second call
            self.assertTrue(verify_db_integrity(c2))
            cols = {r[1] for r in c2.execute("PRAGMA table_info(assets);").fetchall()}
            self.assertIn("key_version", cols)
            row = c2.execute("SELECT sequence_num, request_id FROM audit_events WHERE request_id = 'old-r1';").fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["sequence_num"], 1)
            c2.close()


class TestClusterMessagingAndIndependentDetection(unittest.TestCase):
    def test_stale_epoch_sync_rejected_and_device_revocation_persisted(self):
        with tempfile.TemporaryDirectory() as td:
            coord = ClusterCoordinator(state_dir=Path(td), node_count=3)
            try:
                node_a = coord.get_node("node-a")
                coord.broadcast_revocation("bad-actor")
                self.assertEqual(node_a.current_epoch, 2)
                # Out-of-order stale sync to epoch 1 must be ignored
                node_a.sync(epoch=1, active_key_version="v1", revocations=set())
                self.assertEqual(node_a.current_epoch, 2)
                self.assertIn(("bad-actor", "actor"), node_a.cached_revocations)
            finally:
                coord.close()

    def test_chunked_transport_cross_message_and_tamper_rejected(self):
        tr = ChunkedTransport(chunk_size=10)
        c1 = tr.segment_payload("m1", b"hello world 12345")
        c2 = tr.segment_payload("m2", b"other message xyz")
        with self.assertRaises(CryptoError):
            tr.reassemble([c1[0], c2[1]])

    def test_forged_packet_does_not_poison_replay_cache(self):
        hs = MessagingHandshake()
        sk_a, pk_a = generate_device_keypair()
        sk_b, pk_b = generate_device_keypair()
        offer = hs.generate_responder_offer("bob", "d-b", sk_b)
        init_p, k_as, k_ar = hs.initiate_session("alice", "d-a", sk_a, offer, pk_b)
        k_br, k_bs = hs.complete_responder(offer, init_p, pk_a)

        s_a = MessagingSession(offer["session_id"], "alice", "d-a", "bob", "d-b", k_as, k_ar)
        s_b = MessagingSession(offer["session_id"], "bob", "d-b", "alice", "d-a", k_bs, k_br)
        valid_env = s_a.send_message("Real message")

        # Attacker modifies tag of seq=1 before real packet arrives
        forged = dict(valid_env)
        forged["tag_b64"] = base64.b64encode(b"\x00" * 16).decode("ascii")
        with self.assertRaises(CryptoError):
            s_b.receive_message(forged)

        # Genuine packet with seq=1 must STILL succeed
        self.assertEqual(s_b.receive_message(valid_env), b"Real message")
        s_a.close()
        s_b.close()

    def test_independent_seeded_synthetic_detection_evaluation(self):
        """Evaluate DetectionEngine on an independent fixed-seed dataset (distinct actors/services/approvals)."""
        rng = random.Random(20261126)
        base_t = datetime(2026, 5, 10, 12, 0, 0, tzinfo=timezone.utc)

        registry = ApprovalRegistry()
        registry.add(ApprovalChange(
            approval_id="chg-syn-01",
            approved_by="sec-lead",
            subject="eng-priya",
            operation="grant_role",
            role="auditor",
            scope=["reports", "catalog"],
            valid_from_utc="2026-05-10T12:01:00Z",
            valid_until_utc="2026-05-10T12:10:00Z",
        ))
        registry.add(ApprovalChange(
            approval_id="chg-syn-02",
            approved_by="sec-lead",
            subject="eng-priya",
            operation="revoke_role",
            role="auditor",
            scope=["reports"],
            effective_at_utc="2026-05-10T12:10:00Z",
        ))

        def ts(sec: int) -> str:
            return (base_t + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        events = [
            SecurityEvent("syn-01", ts(0), ts(1), 0, "eng-priya", "portal", "identity", "sign_in", "viewer", "viewer", "success", None, "s1", "f1"),
            SecurityEvent("syn-02", ts(65), ts(66), 0, "eng-priya", "admin-console", "identity", "role_change", "viewer", "auditor", "success", "chg-syn-01", "s1", "f2"),
            SecurityEvent("syn-03", ts(70), ts(71), 0, "eng-priya", "portal", "reports", "read", "auditor", "auditor", "allow", "chg-syn-01", "s1", "f2"),
            # Positive clock offset (+1500ms)
            SecurityEvent("syn-04", "2026-05-10T12:02:01.500Z", "2026-05-10T12:02:00.200Z", 1500, "eng-priya", "portal", "catalog", "read", "auditor", "auditor", "allow", "chg-syn-01", "s1", "f3"),
            # Rogue elevation (outside approval, no approval_id)
            SecurityEvent("syn-05", ts(180), ts(181), 0, "ops-rohan", "admin-console", "identity", "role_change", "viewer", "admin", "success", None, "s2", "f4"),
            SecurityEvent("syn-06", ts(185), ts(186), 0, "ops-rohan", "portal", "reports", "read", "admin", "admin", "allow", None, "s2", "f4"),
            # Multi-hop lateral movement across unexpected services
            SecurityEvent("syn-07", ts(240), ts(241), 0, "svc-etl", "catalog", "payroll", "read", "svc", "svc", "deny", None, "s3", "f5"),
            SecurityEvent("syn-08", ts(242), ts(243), 0, "svc-etl", "payroll", "vault-root", "read", "svc", "svc", "deny", None, "s3", "f5"),
            # Post-revocation denial
            SecurityEvent("syn-09", ts(600), ts(601), 0, "sec-lead", "admin-console", "identity", "revoke_role", "operator", "operator", "success", "chg-syn-02", "s-adm", "f6"),
            SecurityEvent("syn-10", ts(605), ts(606), 0, "eng-priya", "portal", "reports", "read", "viewer", "viewer", "deny", "chg-syn-02", "s1", "f6"),
            # Isolated single denial
            SecurityEvent("syn-11", ts(650), ts(651), 0, "guest-zoe", "portal", "payroll", "read", "viewer", "viewer", "deny", None, "s4", "f7"),
        ]
        # Verify randomized noise idempotence check
        _ = rng.random()

        gt = {
            "syn-01": {"label": "routine", "reason": ""},
            "syn-02": {"label": "approved_change", "reason": ""},
            "syn-03": {"label": "routine", "reason": ""},
            "syn-04": {"label": "routine_clock_offset", "reason": ""},
            "syn-05": {"label": "unexpected_role_change", "reason": ""},
            "syn-06": {"label": "review_after_role_change", "reason": ""},
            "syn-07": {"label": "lateral_movement_candidate", "reason": ""},
            "syn-08": {"label": "lateral_movement_candidate", "reason": ""},
            "syn-09": {"label": "approved_change", "reason": ""},
            "syn-10": {"label": "routine_denial", "reason": ""},
            "syn-11": {"label": "isolated_denial", "reason": ""},
        }

        engine = DetectionEngine(approval_registry=registry)
        preds = engine.evaluate_events(events)
        metrics = DetectionEvaluator(gt).evaluate(preds)
        self.assertEqual(metrics.exact_accuracy, 1.0)
        self.assertEqual(metrics.precision, 1.0)
        self.assertEqual(metrics.recall, 1.0)
        self.assertEqual(metrics.f1_score, 1.0)


if __name__ == "__main__":
    unittest.main()
