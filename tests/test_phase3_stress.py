"""Phase 3 Adversarial Validation, Concurrency, Multi-Process Cluster & Web Security Tests."""
import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from fastapi.testclient import TestClient

from quantumvault.audit.checkpoints import CheckpointManager
from quantumvault.audit.logger import AuditLogger
from quantumvault.backup.backup_manager import BackupManager
from quantumvault.backup.restore import BackupRestoreManager
from quantumvault.core.errors import CryptoError, SecurityPolicyError, StateError
from quantumvault.core.service import QuantumVaultService
from quantumvault.crypto.encryption import AuthenticatedEncryption
from quantumvault.crypto.pqc_kem import MLKEM768
from quantumvault.crypto.rotation import KeyRotationManager
from quantumvault.distributed.authority import read_epoch_anchor, write_epoch_anchor
from quantumvault.distributed.loopback_cluster import LoopbackIPCCluster
from quantumvault.iam.authentication import generate_device_keypair
from quantumvault.iam.device import DeviceManager
from quantumvault.iam.recovery import RecoveryManager
from quantumvault.messaging.handshake import MessagingHandshake
from quantumvault.messaging.outbox import EncryptedOutbox
from quantumvault.messaging.session import MessagingSession
from quantumvault.web.app import app
from quantumvault.web.authentication import get_operator_token

ROOT = Path(__file__).resolve().parent.parent


class TestPhase3AdapterHiddenContract(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.env = os.environ.copy()
        self.env["TRACK4_STATE_DIR"] = self.td.name

    def tearDown(self):
        self.td.cleanup()

    def _run_raw(self, raw_bytes: bytes, env_override: dict[str, str] | None = None) -> tuple[int, str, str]:
        proc = subprocess.Popen(
            [sys.executable, "-B", str(ROOT / "track4_service.py")],
            cwd=str(ROOT),
            env=env_override or self.env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        out_b, err_b = proc.communicate(raw_bytes, timeout=10.0)
        return proc.returncode, out_b.decode("utf-8", errors="replace"), err_b.decode("utf-8", errors="replace")

    def test_duplicate_json_keys_and_invalid_utf8_and_nulls(self):
        # Duplicate JSON keys rejected cleanly (exit 1, no stdout JSON smuggling)
        rc, out, err = self._run_raw(b'{"op":"read","op":"setup","owners":{}}')
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")
        self.assertNotIn("Traceback", err)

        # Invalid UTF-8 bytes rejected safely
        rc2, out2, err2 = self._run_raw(b'\xff\xfe{"op":"read"}')
        self.assertEqual(rc2, 1)
        self.assertEqual(out2, "")
        self.assertNotIn("Traceback", err2)

        # Missing fields / null values / empty strings on read -> deterministic deny
        for bad_read in (
            {"op": "read", "actor": None, "asset": "doc", "request_id": "r1"},
            {"op": "read", "actor": "", "asset": "doc", "request_id": "r1"},
            {"op": "read", "actor": "alice"},
        ):
            rc3, out3, _ = self._run_raw(json.dumps(bad_read).encode("utf-8"))
            self.assertEqual(rc3, 0)
            self.assertEqual(json.loads(out3), {"decision": "deny"})

    def test_nested_missing_state_dir_repeated_ops_and_lock_contention(self):
        nested_dir = Path(self.td.name) / "deep" / "missing" / "state"
        env2 = os.environ.copy()
        env2["TRACK4_STATE_DIR"] = str(nested_dir)

        setup_payload = json.dumps({
            "op": "setup",
            "owners": {"secret-1": "maya"},
            "contents": {"secret-1": "Vault Body 1"},
            "disabled": [],
            "key_material": "seed-lock-test",
        }).encode("utf-8")

        # Repeated initialization cleanly resets state
        rc1, out1, _ = self._run_raw(setup_payload, env_override=env2)
        rc2, out2, _ = self._run_raw(setup_payload, env_override=env2)
        self.assertEqual((rc1, rc2), (0, 0))
        self.assertEqual(json.loads(out2), {"ready": True})

        # Repeated revocation is idempotent
        rev_p = json.dumps({"op": "revoke", "actor": "nobody"}).encode("utf-8")
        r_a, o_a, _ = self._run_raw(rev_p, env_override=env2)
        r_b, o_b, _ = self._run_raw(rev_p, env_override=env2)
        self.assertEqual((r_a, r_b), (0, 0))
        self.assertEqual((json.loads(o_a), json.loads(o_b)), ({}, {}))

        # 8 concurrent OS process reads & audits stressing SQLite WAL busy_timeout
        def worker(idx: int):
            return self._run_raw(
                json.dumps({"op": "read", "actor": "maya", "asset": "secret-1", "request_id": f"par-{idx}"}).encode("utf-8"),
                env_override=env2,
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(worker, range(8)))
        for rc, out, _ in results:
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(out), {"decision": "allow", "body": "Vault Body 1"})

    def test_oversized_input_and_protected_read_bad_b64_and_bad_pk(self):
        self._run_raw(json.dumps({
            "op": "setup",
            "owners": {"a": "alice"},
            "contents": {"a": "hello"},
            "disabled": [],
            "key_material": "seed-pqc-neg",
        }).encode("utf-8"))

        # Bad Base64 & malformed PK return clean deny
        for bad_pk in ("not-valid-b64!!!", base64.b64encode(b"short-key").decode("ascii")):
            rc, out, err = self._run_raw(json.dumps({
                "op": "protected_read",
                "actor": "alice",
                "asset": "a",
                "challenge": "ch-1",
                "public_key": bad_pk,
            }).encode("utf-8"))
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(out), {"decision": "deny"})
            self.assertNotIn("Traceback", err)

        # > 64 KiB legitimate setup payload MUST succeed per Adapter Contract v1 EOF rule
        big_body = "B" * 80000
        rc_setup, out_setup, err_setup = self._run_raw(json.dumps({
            "op": "setup",
            "owners": {"big-doc": "alice"},
            "contents": {"big-doc": big_body},
            "disabled": [],
            "key_material": "seed-large-setup",
        }).encode("utf-8"))
        self.assertEqual(rc_setup, 0, err_setup)
        self.assertEqual(json.loads(out_setup), {"ready": True})

        rc_read, out_read, _ = self._run_raw(json.dumps({
            "op": "read",
            "actor": "alice",
            "asset": "big-doc",
            "request_id": "big-read-1",
        }).encode("utf-8"))
        self.assertEqual(rc_read, 0)
        self.assertEqual(json.loads(out_read), {"decision": "allow", "body": big_body})

        # Single non-setup lookup > 64 KiB (e.g., 70 KB request_id) rejected cleanly with exit 1
        rc_over_read, out_over_read, _ = self._run_raw(json.dumps({
            "op": "read",
            "actor": "alice",
            "asset": "big-doc",
            "request_id": "r" * 70000,
        }).encode("utf-8"))
        self.assertEqual(rc_over_read, 1)
        self.assertEqual(out_over_read, "")

        # >10 MiB payload rejected cleanly with exit 1
        oversized = b'{"op":"setup","owners":{},"contents":{"x":"' + (b"x" * (10 * 1024 * 1024 + 50)) + b'"}}'
        rc_big, out_big, _ = self._run_raw(oversized)
        self.assertEqual(rc_big, 1)
        self.assertEqual(out_big, "")


class TestPhase3MultiProcessCluster(unittest.TestCase):
    def test_independent_multiprocess_cluster_partition_crash_and_sync(self):
        with tempfile.TemporaryDirectory() as td:
            cluster = LoopbackIPCCluster(Path(td))
            try:
                cluster.setup_all(
                    owners={"doc-mp": "alice", "doc-peer": "bob"},
                    contents={"doc-mp": "MultiProcess Confidential", "doc-peer": "Peer Secret"},
                    disabled=[],
                    key_material="mp-cluster-seed",
                )

                # Separate DB paths verified per worker process
                db_paths = {cluster.status(n)["db_path"] for n in ("node-a", "node-b", "node-c")}
                self.assertEqual(len(db_paths), 3)

                # 1. Authorized concurrent reads across all 3 separate OS node processes
                for n in ("node-a", "node-b", "node-c"):
                    r = cluster.read(n, "alice", "doc-mp", f"mp-init-{n}")
                    self.assertEqual(r["decision"], "allow")
                    self.assertEqual(r["body"], "MultiProcess Confidential")

                # 2. Simulate 2 nodes unreachable/partitioned -> fail-closed
                cluster.set_fault("node-b", authority_reachable=False)
                cluster.set_fault("node-c", online=False)
                self.assertEqual(cluster.read("node-b", "bob", "doc-peer", "p-b")["rule"], "node_offline_fail_closed")
                self.assertEqual(cluster.read("node-c", "bob", "doc-peer", "p-c")["rule"], "node_offline_fail_closed")

                # 3. Reconnect node-b only, keep node-c dead/killed while revocation commits at authority
                cluster.set_fault("node-b", online=True, authority_reachable=True, refresh_heartbeat=True)
                cluster.kill_node("node-c")

                rev = cluster.broadcast_revocation("alice", reason="compromised_laptop")
                self.assertEqual(rev["epoch"], 2)
                self.assertIn("node-a", rev["confirmed_nodes"])
                self.assertIn("node-b", rev["confirmed_nodes"])
                self.assertNotIn("node-c", rev["confirmed_nodes"])

                # 4. Restart crashed node-c with outdated local DB (auto_sync=False) -> MUST fail closed until synced
                cluster.restart_node("node-c", auto_sync=False)
                stale_probe = cluster.read("node-c", "bob", "doc-peer", "stale-c-1")
                self.assertEqual(stale_probe["decision"], "deny")
                self.assertEqual(stale_probe["rule"], "node_offline_fail_closed")

                # 5. Stale out-of-order epoch 1 rejected on node-a (at epoch 2)
                stale_sync = cluster.send_raw_ipc("node-a", {
                    "cmd": "sync",
                    "epoch": 1,
                    "active_key_version": "v1",
                    "revocations": [],
                })
                self.assertTrue(stale_sync.get("ignored_stale_epoch"))
                self.assertEqual(cluster.status("node-a")["epoch"], 2)

                # 6. Sync node-c -> reconciles epoch 2 & revocations, enforces denial on alice while bob works
                cluster.sync_node("node-c")
                self.assertEqual(cluster.status("node-c")["epoch"], 2)
                self.assertEqual(cluster.read("node-c", "alice", "doc-mp", "c-denied")["decision"], "deny")
                self.assertEqual(cluster.read("node-c", "bob", "doc-peer", "c-allow")["decision"], "allow")
            finally:
                cluster.close()


class TestPhase3ConcurrencyAndCrashRecovery(unittest.TestCase):
    def test_concurrent_readers_revocation_recovery_replay_and_outbox(self):
        with tempfile.TemporaryDirectory() as td:
            sd = Path(td)
            svc = QuantumVaultService(state_dir=sd)
            try:
                svc.setup({"d1": "alice", "d2": "bob"}, {"d1": "BodyA", "d2": "BodyB"}, [], "conc-seed")
                _, pk = generate_device_keypair()
                DeviceManager(svc.conn).enroll_device("alice", "dev-a1", pk)
                code = RecoveryManager(svc.conn).generate_recovery_codes("alice", count=1)[0]

                # A. 50-thread barrier concurrent recovery-code redemption -> strictly 1 succeeds
                barrier = threading.Barrier(20)
                def redeem_one(i: int) -> bool:
                    c = svc.conn
                    # Each thread opens own SQLite connection sharing WAL file
                    from quantumvault.storage.db import get_connection
                    tconn = get_connection(svc.db_path)
                    try:
                        barrier.wait(timeout=5.0)
                        return RecoveryManager(tconn).verify_and_consume("alice", code)
                    finally:
                        tconn.close()

                with ThreadPoolExecutor(max_workers=20) as pool:
                    redeem_outcomes = list(pool.map(redeem_one, range(20)))
                self.assertEqual(sum(1 for x in redeem_outcomes if x), 1)

                # B. 20-thread barrier concurrent duplicate AEAD message replay -> strictly 1 succeeds
                hs = MessagingHandshake()
                sk_a, pk_a = generate_device_keypair()
                sk_b, pk_b = generate_device_keypair()
                offer = hs.generate_responder_offer("bob", "dev-b", sk_b)
                init_p, k_as, k_ar = hs.initiate_session("alice", "dev-a1", sk_a, offer, pk_b)
                k_br, k_bs = hs.complete_responder(offer, init_p, pk_a)
                s_a = MessagingSession(offer["session_id"], "alice", "dev-a1", "bob", "dev-b", k_as, k_ar)
                s_b = MessagingSession(offer["session_id"], "bob", "dev-b", "alice", "dev-a1", k_bs, k_br, conn=svc.conn)
                env = s_a.send_message("Synchronized replay race test")

                rep_barrier = threading.Barrier(20)
                def replay_one(_: int) -> bool:
                    rep_barrier.wait(timeout=5.0)
                    try:
                        s_b.receive_message(env)
                        return True
                    except (SecurityPolicyError, CryptoError):
                        return False

                with ThreadPoolExecutor(max_workers=20) as pool:
                    rep_outcomes = list(pool.map(replay_one, range(20)))
                self.assertEqual(sum(1 for x in rep_outcomes if x), 1)
                s_a.close()
                s_b.close()

                # C. 10-thread barrier concurrent OfflineOutbox.flush() -> strictly 1 dispatch per queued message
                outbox = EncryptedOutbox(svc.conn, b"K" * 32)
                outbox.enqueue("alice", "dev-a1", "bob", "Single delivery only")
                dispatched: list[str] = []
                disp_lock = threading.Lock()
                flush_barrier = threading.Barrier(10)

                def flush_worker(_: int):
                    from quantumvault.storage.db import get_connection
                    tconn = get_connection(svc.db_path)
                    try:
                        flush_barrier.wait(timeout=5.0)
                        ob = EncryptedOutbox(tconn, b"K" * 32)
                        ob.flush("alice", lambda a, r, p: (disp_lock.acquire() or True) and (dispatched.append(p.decode()), disp_lock.release(), True)[-1])
                    finally:
                        tconn.close()

                with ThreadPoolExecutor(max_workers=10) as pool:
                    list(pool.map(flush_worker, range(10)))
                self.assertEqual(len(dispatched), 1)

                # D. 100 concurrent authorized reads + audit writes during backup creation
                bak_mgr = BackupManager(state_dir=sd)
                def read_or_backup(i: int):
                    from quantumvault.storage.db import get_connection
                    from quantumvault.storage.db import transaction
                    if i == 50:
                        return bak_mgr.create_backup(sd / "concurrent.qvb")["snapshot_sha256"]
                    tconn = get_connection(svc.db_path)
                    try:
                        local_svc = QuantumVaultService(db_path=svc.db_path, state_dir=sd)
                        res = local_svc.read("bob", "d2", f"c-read-{i}")
                        local_svc.close()
                        return res["decision"]
                    finally:
                        tconn.close()

                with ThreadPoolExecutor(max_workers=12) as pool:
                    mix_res = list(pool.map(read_or_backup, range(100)))
                self.assertEqual(sum(1 for r in mix_res if r == "allow"), 99)
                self.assertEqual(len(str(mix_res[50])), 64)
            finally:
                svc.close()

    def test_rotation_zero_grace_and_corrupted_anchor_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            sd = Path(td)
            svc = QuantumVaultService(state_dir=sd)
            try:
                svc.setup({"doc": "alice"}, {"doc": "SecretZeroGrace"}, [], "zero-grace-seed")
                from quantumvault.config import get_checkpoint_key_path, get_epoch_anchor_path, get_vault_key_path
                from quantumvault.crypto.key_manager import load_vault_key

                kek = load_vault_key(get_vault_key_path(sd))
                rot = KeyRotationManager(svc.conn, kek)
                # Immediate cutoff rotation (grace_seconds=0.0) must still atomically rewrap assets!
                res = rot.rotate_key("v2", grace_seconds=0.0, rewrap_assets=True)
                self.assertEqual(res["rewrapped_count"], 1)
                self.assertEqual(svc.read("alice", "doc", "after-zero-grace")["body"], "SecretZeroGrace")

                # Corrupted .cluster_epoch_anchor must fail closed with StateError
                anchor_path = get_epoch_anchor_path(sd)
                write_epoch_anchor(sd, 3)
                self.assertEqual(read_epoch_anchor(sd), 3)
                anchor_path.write_text("v1:3:corrupteddigest", encoding="utf-8")
                with self.assertRaises(StateError):
                    read_epoch_anchor(sd)

                # Corrupted .audit_checkpoint.key (wrong byte length) must fail closed with CryptoError
                chk_mgr = CheckpointManager(svc.conn, external_file_path=sd / "ext_chk.json")
                chk_mgr.create_checkpoint("c1")
                get_checkpoint_key_path(sd).write_bytes(b"short")
                with self.assertRaises(CryptoError):
                    CheckpointManager(svc.conn, external_file_path=sd / "ext_chk.json")
            finally:
                svc.close()


class TestPhase3CryptoAndWebSecurity(unittest.TestCase):
    def test_mlkem768_vectors_aead_nonce_uniqueness_and_web_csrf_host(self):
        # 1. Verify ML-KEM-768 standard FIPS 203 byte sizes
        kem = MLKEM768()
        pk, sk = kem.generate_keypair()
        self.assertEqual(len(pk), 1184)
        self.assertEqual(len(sk), 2400)
        ct, ss1 = kem.encapsulate(pk)
        self.assertEqual(len(ct), 1088)
        self.assertEqual(len(ss1), 32)
        ss2 = kem.decapsulate(sk, ct)
        self.assertEqual(ss1, ss2)

        # 2. Verify AES-256-GCM nonce uniqueness over 500 encryptions
        cipher = AuthenticatedEncryption(b"M" * 32)
        nonces = set()
        for i in range(500):
            _, nonce = cipher.encrypt_bytes(f"msg-{i}".encode("utf-8"), associated_data=b"aad")
            nonces.add(nonce)
        self.assertEqual(len(nonces), 500)

        # 3. Verify Web API CSRF, Host header, Origin validation & Session Rotation
        client = TestClient(app)
        token = get_operator_token()

        # Cookie-only mutation (CSRF simulation without X-Operator-Token header) must fail 401
        client.cookies.set("qv_operator_token", token)
        csrf_post = client.post("/api/v1/crypto/rotate-key", headers={"host": "127.0.0.1:8000"})
        self.assertEqual(csrf_post.status_code, 401)
        client.cookies.clear()

        # Untrusted Host header rejected 403
        bad_host = client.get("/api/v1/status", headers={"X-Operator-Token": token, "host": "evil.attacker.local"})
        self.assertEqual(bad_host.status_code, 403)

        # Cross-origin POST rejected 403
        bad_origin = client.post(
            "/api/v1/crypto/rotate-key",
            headers={"X-Operator-Token": token, "host": "127.0.0.1:8000", "Origin": "https://evil.attacker.local"},
        )
        self.assertEqual(bad_origin.status_code, 403)

        # New endpoints return live backend metrics
        cmp_res = client.get("/api/v1/detection/evaluation-comparison", headers={"X-Operator-Token": token})
        self.assertEqual(cmp_res.status_code, 200)
        cmp_data = cmp_res.json()
        self.assertEqual(cmp_data["practice"]["total_events"], 22)
        self.assertEqual(cmp_data["practice"]["f1_score"], 1.0)
        self.assertGreaterEqual(cmp_data["held_out_synthetic"]["total_events"], 900)
        self.assertEqual(cmp_data["held_out_synthetic"]["f1_score"], 1.0)

        # Session token rotation invalidates prior token immediately
        rot_res = client.post("/api/v1/auth/rotate", headers={"X-Operator-Token": token})
        self.assertEqual(rot_res.status_code, 200)
        new_tok = rot_res.json()["new_token"]
        self.assertNotEqual(new_tok, token)
        old_rejected = client.get("/api/v1/status", headers={"X-Operator-Token": token})
        self.assertEqual(old_rejected.status_code, 401)
        new_ok = client.get("/api/v1/status", headers={"X-Operator-Token": new_tok})
        self.assertEqual(new_ok.status_code, 200)

        # Logout invalidates active session token immediately
        out_res = client.post("/api/v1/auth/logout", headers={"X-Operator-Token": new_tok})
        self.assertEqual(out_res.status_code, 200)
        self.assertEqual(client.get("/api/v1/status", headers={"X-Operator-Token": new_tok}).status_code, 401)


if __name__ == "__main__":
    unittest.main()
