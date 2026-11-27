"""Comprehensive performance benchmark suite for QuantumVault (Section 16).

Measures median, p95, p99, and max latencies across:
- Headless adapter CLI request latency
- Authorized vs unauthorized read latency
- Key rotation & asset rewrapping latency
- Multi-node revocation propagation latency
- Audit hash chain verification latency
- Deterministic threat detection latency (practice + synthetic)
- Post-quantum ML-KEM-768 + ML-DSA-65 handshake latency
- AES-256-GCM message encrypt/decrypt latency
- Backup creation and anti-rollback restore latency
- Legacy database migration latency
"""
from datetime import datetime, timezone
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from quantumvault.audit.logger import AuditLogger
from quantumvault.audit.verifier import AuditLogVerifier
from quantumvault.backup.backup_manager import BackupManager
from quantumvault.backup.restore import BackupRestoreManager
from quantumvault.config import get_vault_key_path
from quantumvault.core.service import QuantumVaultService
from quantumvault.crypto.key_manager import load_vault_key
from quantumvault.crypto.rotation import KeyRotationManager
from quantumvault.detection.engine import DetectionEngine
from quantumvault.detection.ingestion import load_approvals_from_json, load_events_from_csv
from quantumvault.distributed.cluster import ClusterCoordinator
from quantumvault.iam.authentication import generate_device_keypair, generate_pqc_device_keypair
from quantumvault.messaging.e2ee import MessageCipher
from quantumvault.messaging.handshake import MessagingHandshake
from quantumvault.storage.db import get_connection, init_db


def _stats(samples_ms: list[float]) -> dict[str, Any]:
    s = sorted(samples_ms)
    n = len(s)
    if n == 0:
        return {"samples": 0, "median_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0, "max_ms": 0.0}
    p95 = s[min(n - 1, int(0.95 * (n - 1)))]
    p99 = s[min(n - 1, int(0.99 * (n - 1)))]
    return {
        "samples": n,
        "median_ms": round(statistics.median(s), 4),
        "p95_ms": round(p95, 4),
        "p99_ms": round(p99, 4),
        "max_ms": round(s[-1], 4),
    }


def run_all_benchmarks() -> dict[str, Any]:
    results: dict[str, Any] = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "os": platform.platform(),
            "processor": platform.processor() or platform.machine(),
            "cpu_count": os.cpu_count(),
            "python_version": platform.python_version(),
            "packages": {
                pkg: importlib.metadata.version(pkg)
                for pkg in ("pqcrypto", "cryptography", "fastapi", "uvicorn", "pydantic", "httpx")
            },
        },
        "benchmarks": {},
    }

    # 1. Headless adapter subprocess latency (10 reads)
    with tempfile.TemporaryDirectory() as td:
        env = os.environ.copy()
        env["TRACK4_STATE_DIR"] = td
        setup_req = json.dumps({
            "op": "setup",
            "owners": {"doc1": "alice"},
            "contents": {"doc1": "Benchmark body"},
            "disabled": [],
            "key_material": "bench-seed",
        })
        subprocess.run([sys.executable, "-B", str(ROOT_DIR / "track4_service.py")], input=setup_req, env=env, cwd=str(ROOT_DIR), capture_output=True, text=True, check=True)
        cli_times = []
        for i in range(10):
            req = json.dumps({"op": "read", "actor": "alice", "asset": "doc1", "request_id": f"b-{i}"})
            t0 = time.perf_counter()
            p = subprocess.run([sys.executable, "-B", str(ROOT_DIR / "track4_service.py")], input=req, env=env, cwd=str(ROOT_DIR), capture_output=True, text=True, check=True)
            cli_times.append((time.perf_counter() - t0) * 1000.0)
            assert json.loads(p.stdout)["decision"] == "allow"
        results["benchmarks"]["adapter_subprocess_read"] = _stats(cli_times)

    # 2. In-process authorized & unauthorized read latency (100 samples each)
    with tempfile.TemporaryDirectory() as td:
        svc = QuantumVaultService(state_dir=Path(td))
        svc.setup({"doc1": "alice"}, {"doc1": "Benchmark secret"}, ["mallory"], "bench-seed")
        auth_times, unauth_times = [], []
        for i in range(100):
            t0 = time.perf_counter()
            r1 = svc.read("alice", "doc1", f"auth-{i}")
            auth_times.append((time.perf_counter() - t0) * 1000.0)
            assert r1["decision"] == "allow"

            t1 = time.perf_counter()
            r2 = svc.read("mallory", "doc1", f"unauth-{i}")
            unauth_times.append((time.perf_counter() - t1) * 1000.0)
            assert r2["decision"] == "deny"
        svc.close()
        results["benchmarks"]["authorized_read"] = _stats(auth_times)
        results["benchmarks"]["unauthorized_read"] = _stats(unauth_times)

    # 3. Key rotation latency (100 assets, 10 samples)
    rot_times = []
    for _ in range(10):
        with tempfile.TemporaryDirectory() as td:
            sd = Path(td)
            svc = QuantumVaultService(state_dir=sd)
            owners = {f"a-{i}": "alice" for i in range(100)}
            contents = {f"a-{i}": f"Body-{i}" for i in range(100)}
            svc.setup(owners, contents, [], "rot-bench")
            kek = load_vault_key(get_vault_key_path(sd))
            rot = KeyRotationManager(svc.conn, kek)
            t0 = time.perf_counter()
            rot.rotate_key("v2", grace_seconds=10.0, rewrap_assets=True)
            rot_times.append((time.perf_counter() - t0) * 1000.0)
            svc.close()
    results["benchmarks"]["key_rotation_100_assets"] = _stats(rot_times)

    # 4. 3-node revocation propagation latency (30 samples)
    prop_times = []
    with tempfile.TemporaryDirectory() as td:
        coord = ClusterCoordinator(state_dir=Path(td), node_count=3)
        for i in range(30):
            res = coord.broadcast_revocation(f"rev-{i}")
            prop_times.append(res["total_propagation_ms"])
        coord.close()
    results["benchmarks"]["cluster_revocation_propagation_3nodes"] = _stats(prop_times)

    # 5. Audit verification latency (1000 events, 10 samples)
    aud_times = []
    with tempfile.TemporaryDirectory() as td:
        conn = get_connection(Path(td) / "aud.db")
        init_db(conn)
        logger = AuditLogger(conn)
        for i in range(1000):
            logger.log_decision(f"r-{i}", "alice", "read", "doc1", "allow", "owner_allowed")
        verifier = AuditLogVerifier(conn)
        for _ in range(10):
            t0 = time.perf_counter()
            rep = verifier.verify()
            aud_times.append((time.perf_counter() - t0) * 1000.0)
            assert rep["status"] == "valid"
        conn.close()
    results["benchmarks"]["audit_verify_1000_events"] = _stats(aud_times)

    # 6. Threat detection latency (22 practice events, 50 samples)
    events = load_events_from_csv(ROOT_DIR / "references" / "track4-toolkit" / "practice" / "events.csv")
    approvals = load_approvals_from_json(ROOT_DIR / "references" / "track4-toolkit" / "practice" / "approvals.json")
    det_times = []
    for _ in range(50):
        eng = DetectionEngine(approval_registry=approvals)
        t0 = time.perf_counter()
        eng.evaluate_events(events)
        det_times.append((time.perf_counter() - t0) * 1000.0)
    results["benchmarks"]["threat_detection_22_events"] = _stats(det_times)

    # 7. PQC handshake (ML-KEM-768 + ML-DSA-65, 25 samples)
    hs_times = []
    hs = MessagingHandshake()
    sk_a, pk_a = generate_pqc_device_keypair()
    sk_b, pk_b = generate_pqc_device_keypair()
    for _ in range(25):
        t0 = time.perf_counter()
        offer = hs.generate_responder_offer("bob", "d-b", sk_b)
        init_p, _, _ = hs.initiate_session("alice", "d-a", sk_a, offer, pk_b)
        hs.complete_responder(offer, init_p, pk_a)
        hs_times.append((time.perf_counter() - t0) * 1000.0)
    results["benchmarks"]["pqc_handshake_mlkem768_mldsa65"] = _stats(hs_times)

    # 8. Message AES-256-GCM encrypt & decrypt latency (200 samples)
    cipher = MessageCipher(b"M" * 32, "s-bench", "alice", "d-a", "bob", "d-b")
    enc_times, dec_times = [], []
    for i in range(200):
        t0 = time.perf_counter()
        env = cipher.encrypt_message("Benchmark payload message", sequence_num=i + 1)
        enc_times.append((time.perf_counter() - t0) * 1000.0)
        t1 = time.perf_counter()
        cipher.decrypt_message(env)
        dec_times.append((time.perf_counter() - t1) * 1000.0)
    results["benchmarks"]["message_aead_encrypt"] = _stats(enc_times)
    results["benchmarks"]["message_aead_decrypt"] = _stats(dec_times)

    # 9. Backup creation & restore latency (15 samples)
    bak_times, rest_times = [], []
    for i in range(15):
        with tempfile.TemporaryDirectory() as td:
            sd = Path(td)
            svc = QuantumVaultService(state_dir=sd)
            svc.setup({"doc": "alice"}, {"doc": "Backup benchmark payload"}, [], "bak-bench")
            svc.close()
            bm = BackupManager(state_dir=sd)
            bp = sd / f"b-{i}.qvb"
            t0 = time.perf_counter()
            bm.create_backup(bp)
            bak_times.append((time.perf_counter() - t0) * 1000.0)
            rm = BackupRestoreManager(state_dir=sd)
            t1 = time.perf_counter()
            rm.verify_and_restore(bp)
            rest_times.append((time.perf_counter() - t1) * 1000.0)
    results["benchmarks"]["backup_create"] = _stats(bak_times)
    results["benchmarks"]["backup_verify_restore"] = _stats(rest_times)

    # 10. Legacy database migration latency (15 samples)
    mig_times = []
    for _ in range(15):
        with tempfile.TemporaryDirectory() as td:
            dbp = Path(td) / "leg.db"
            c = sqlite3.connect(str(dbp))
            c.executescript("""
                CREATE TABLE identities (actor_id TEXT PRIMARY KEY, status TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'viewer');
                CREATE TABLE assets (asset_id TEXT PRIMARY KEY, owner_actor_id TEXT NOT NULL, encrypted_body BLOB NOT NULL, nonce BLOB NOT NULL);
                CREATE TABLE audit_events (request_id TEXT PRIMARY KEY, event_time_utc TEXT NOT NULL, actor_id TEXT NOT NULL, op TEXT NOT NULL, asset_id TEXT, decision TEXT NOT NULL, rule TEXT NOT NULL, entry_hash TEXT NOT NULL);
            """)
            c.close()
            c2 = get_connection(dbp)
            t0 = time.perf_counter()
            init_db(c2)
            mig_times.append((time.perf_counter() - t0) * 1000.0)
            c2.close()
    results["benchmarks"]["legacy_db_migration"] = _stats(mig_times)

    return results


if __name__ == "__main__":
    report = run_all_benchmarks()
    print(json.dumps(report, indent=2))
