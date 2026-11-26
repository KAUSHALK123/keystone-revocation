"""Comprehensive Performance Benchmarking Suite for QuantumVault Phase 1.2.

Measures:
1. Device Authentication & Ed25519 Challenge-Response Latency
2. Recovery Credential Generation & Atomic Consumption Latency
3. Key Rotation & Asset Re-wrapping Latency (10, 50, 100 assets)
4. Multi-Node Cluster Revocation Broadcast & Propagation Latency (Nodes A, B, C)
5. Authenticated AES-GCM Backup Creation & Anti-Rollback Restore Latency
6. Cryptographic Audit Hash Chaining & Full Chain Verification Latency (100, 500, 1000 events)
"""
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from quantumvault.audit.checkpoints import CheckpointManager
from quantumvault.audit.logger import AuditLogger
from quantumvault.audit.verifier import AuditLogVerifier
from quantumvault.backup.backup_manager import BackupManager
from quantumvault.backup.restore import BackupRestoreManager
from quantumvault.config import get_vault_key_path
from quantumvault.core.service import QuantumVaultService
from quantumvault.crypto.key_manager import load_vault_key
from quantumvault.crypto.rotation import KeyRotationManager
from quantumvault.distributed.cluster import ClusterCoordinator
from quantumvault.iam.authentication import (
    DeviceAuthenticator,
    generate_device_keypair,
    sign_challenge,
)
from quantumvault.iam.device import DeviceManager
from quantumvault.iam.recovery import RecoveryManager
from quantumvault.storage.db import get_connection, init_db, transaction


def benchmark_device_auth(iterations: int = 200) -> dict:
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "auth_bench.db"
        conn = get_connection(db_path)
        init_db(conn)
        with transaction(conn):
            conn.execute("INSERT INTO identities (actor_id, status, role) VALUES ('alice', 'active', 'viewer');")
        
        dev_mgr = DeviceManager(conn)
        auth = DeviceAuthenticator(conn)
        priv, pub = generate_device_keypair()
        dev_mgr.enroll_device("alice", "dev-alice", pub)

        key_gen_latencies = []
        chal_resp_latencies = []

        for _ in range(iterations):
            # Key generation latency
            t0 = time.perf_counter()
            p, pb = generate_device_keypair()
            key_gen_latencies.append((time.perf_counter() - t0) * 1000.0)

            # Challenge-response roundtrip latency
            t1 = time.perf_counter()
            c = auth.create_challenge("dev-alice")["challenge"]
            s = sign_challenge(priv, c)
            ok = auth.verify_response("dev-alice", c, s)
            t2 = time.perf_counter()
            assert ok is True
            chal_resp_latencies.append((t2 - t1) * 1000.0)

        conn.close()

    return {
        "iterations": iterations,
        "key_generation_mean_ms": round(statistics.mean(key_gen_latencies), 4),
        "key_generation_p95_ms": round(statistics.quantiles(key_gen_latencies, n=20)[18], 4),
        "challenge_response_roundtrip_mean_ms": round(statistics.mean(chal_resp_latencies), 4),
        "challenge_response_roundtrip_p95_ms": round(statistics.quantiles(chal_resp_latencies, n=20)[18], 4),
    }


def benchmark_recovery_codes(iterations: int = 50) -> dict:
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "rec_bench.db"
        conn = get_connection(db_path)
        init_db(conn)
        with transaction(conn):
            conn.execute("INSERT INTO identities (actor_id, status, role) VALUES ('alice', 'active', 'viewer');")

        rec_mgr = RecoveryManager(conn)
        gen_latencies = []
        consume_latencies = []

        for _ in range(iterations):
            t0 = time.perf_counter()
            codes = rec_mgr.generate_recovery_codes("alice", count=5)
            gen_latencies.append((time.perf_counter() - t0) * 1000.0)

            t1 = time.perf_counter()
            consumed = rec_mgr.verify_and_consume("alice", codes[0])
            consume_latencies.append((time.perf_counter() - t1) * 1000.0)
            assert consumed is True

        conn.close()

    return {
        "iterations": iterations,
        "code_generation_5x_mean_ms": round(statistics.mean(gen_latencies), 4),
        "code_consumption_mean_ms": round(statistics.mean(consume_latencies), 4),
        "code_consumption_p95_ms": round(statistics.quantiles(consume_latencies, n=20)[18], 4),
    }


def benchmark_key_rotation(asset_counts: list[int] = [10, 50, 100]) -> dict:
    results = {}
    for count in asset_counts:
        with tempfile.TemporaryDirectory() as td:
            state_dir = Path(td)
            service = QuantumVaultService(state_dir=state_dir)
            owners = {f"asset-{i}": "alice" for i in range(count)}
            contents = {f"asset-{i}": f"Confidential Payload Content {i}" for i in range(count)}
            service.setup(owners=owners, contents=contents, disabled=[], key_material="bench-key-material")

            kek = load_vault_key(get_vault_key_path(state_dir))
            rot_mgr = KeyRotationManager(service.conn, kek)

            t0 = time.perf_counter()
            rot_res = rot_mgr.rotate_key("v2", grace_seconds=60.0, rewrap_assets=True)
            t_rot = (time.perf_counter() - t0) * 1000.0

            assert rot_res["rewrapped_count"] == count
            service.close()

            results[f"{count}_assets"] = {
                "total_rotation_time_ms": round(t_rot, 4),
                "per_asset_rewrap_time_ms": round(t_rot / count, 4),
            }

    return results


def benchmark_cluster_propagation(iterations: int = 50) -> dict:
    with tempfile.TemporaryDirectory() as td:
        state_dir = Path(td)
        service = QuantumVaultService(state_dir=state_dir)
        service.setup(
            owners={"doc-1": "owner-1"},
            contents={"doc-1": "Secret"},
            disabled=[],
            key_material="cluster-bench-key"
        )
        service.close()

        cluster = ClusterCoordinator(state_dir=state_dir, node_count=3)
        bcast_latencies = []
        node_a_latencies = []
        node_b_latencies = []
        node_c_latencies = []

        for i in range(iterations):
            res = cluster.broadcast_revocation(f"actor-{i}", entity_type="actor")
            bcast_latencies.append(res["total_propagation_ms"])
            node_a_latencies.append(res["node_latencies_ms"]["node-a"])
            node_b_latencies.append(res["node_latencies_ms"]["node-b"])
            node_c_latencies.append(res["node_latencies_ms"]["node-c"])

        cluster.close()

    return {
        "nodes": ["node-a", "node-b", "node-c"],
        "iterations": iterations,
        "total_propagation_mean_ms": round(statistics.mean(bcast_latencies), 4),
        "total_propagation_p95_ms": round(statistics.quantiles(bcast_latencies, n=20)[18], 4),
        "node_a_mean_ms": round(statistics.mean(node_a_latencies), 4),
        "node_b_mean_ms": round(statistics.mean(node_b_latencies), 4),
        "node_c_mean_ms": round(statistics.mean(node_c_latencies), 4),
    }


def benchmark_backup_and_restore(iterations: int = 20) -> dict:
    with tempfile.TemporaryDirectory() as td:
        state_dir = Path(td)
        service = QuantumVaultService(state_dir=state_dir)
        owners = {f"file-{i}": f"user-{i % 5}" for i in range(50)}
        contents = {f"file-{i}": f"Content body for asset {i}" for i in range(50)}
        service.setup(owners=owners, contents=contents, disabled=[], key_material="backup-bench-key")
        service.close()

        backup_mgr = BackupManager(state_dir=state_dir)
        restore_mgr = BackupRestoreManager(state_dir=state_dir)
        backup_file = state_dir / "bench_backup.qvb"

        backup_times = []
        restore_times = []

        for _ in range(iterations):
            t0 = time.perf_counter()
            meta = backup_mgr.create_backup(backup_file)
            backup_times.append((time.perf_counter() - t0) * 1000.0)

            t1 = time.perf_counter()
            res = restore_mgr.verify_and_restore(backup_file)
            restore_times.append((time.perf_counter() - t1) * 1000.0)
            assert res["restored"] is True

    return {
        "iterations": iterations,
        "backup_creation_mean_ms": round(statistics.mean(backup_times), 4),
        "backup_creation_p95_ms": round(statistics.quantiles(backup_times, n=20)[18], 4),
        "backup_restore_mean_ms": round(statistics.mean(restore_times), 4),
        "backup_restore_p95_ms": round(statistics.quantiles(restore_times, n=20)[18], 4),
        "backup_size_bytes": meta["backup_size_bytes"],
    }


def benchmark_audit_chain(event_counts: list[int] = [100, 500, 1000]) -> dict:
    results = {}
    for count in event_counts:
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "audit_bench.db"
            conn = get_connection(db_path)
            init_db(conn)
            logger = AuditLogger(conn)

            # Measure logging (hash chaining)
            t0 = time.perf_counter()
            with transaction(conn):
                for i in range(count):
                    logger.log_decision(
                        request_id=f"req-{i}",
                        actor_id=f"actor-{i % 10}",
                        op="read",
                        asset_id=f"asset-{i % 5}",
                        decision="allow" if i % 2 == 0 else "deny",
                        rule="owner_allowed" if i % 2 == 0 else "owner_required"
                    )
            t_log = (time.perf_counter() - t0) * 1000.0

            # Create checkpoint
            chk_mgr = CheckpointManager(conn)
            t_chk0 = time.perf_counter()
            chk = chk_mgr.create_checkpoint(f"chk-{count}")
            t_chk = (time.perf_counter() - t_chk0) * 1000.0

            # Measure full chain verification
            verifier = AuditLogVerifier(conn)
            t_v0 = time.perf_counter()
            rep = verifier.verify()
            t_v = (time.perf_counter() - t_v0) * 1000.0

            assert rep["status"] == "valid"
            assert rep["total_records"] == count
            conn.close()

            results[f"{count}_events"] = {
                "logging_total_ms": round(t_log, 4),
                "logging_per_event_ms": round(t_log / count, 4),
                "checkpoint_creation_ms": round(t_chk, 4),
                "full_verification_ms": round(t_v, 4),
                "verification_per_event_ms": round(t_v / count, 4),
            }

    return results


def run_all_benchmarks() -> dict:
    print("=" * 70)
    print("QUANTUMVAULT PHASE 1.2 PERFORMANCE BENCHMARKING SUITE")
    print("=" * 70)

    print("\n[1/6] Benchmarking Device Authentication & Proof-of-Possession...")
    device_auth_results = benchmark_device_auth()
    print(f"      Key Generation (mean): {device_auth_results['key_generation_mean_ms']:.4f} ms")
    print(f"      Challenge-Response Roundtrip (mean): {device_auth_results['challenge_response_roundtrip_mean_ms']:.4f} ms")

    print("\n[2/6] Benchmarking Recovery Credentials...")
    recovery_results = benchmark_recovery_codes()
    print(f"      Recovery Code Generation (5 codes): {recovery_results['code_generation_5x_mean_ms']:.4f} ms")
    print(f"      Atomic Code Verification & Consumption: {recovery_results['code_consumption_mean_ms']:.4f} ms")

    print("\n[3/6] Benchmarking Key Rotation & Asset Re-wrapping...")
    rotation_results = benchmark_key_rotation()
    for scale, data in rotation_results.items():
        print(f"      {scale}: Total = {data['total_rotation_time_ms']:.2f} ms | Per-Asset = {data['per_asset_rewrap_time_ms']:.4f} ms")

    print("\n[4/6] Benchmarking Multi-Node Cluster Propagation (Nodes A, B, C)...")
    cluster_results = benchmark_cluster_propagation()
    print(f"      Total 3-Node Propagation (mean): {cluster_results['total_propagation_mean_ms']:.4f} ms (p95: {cluster_results['total_propagation_p95_ms']:.4f} ms)")
    print(f"      Per-Node Delivery Latency: A={cluster_results['node_a_mean_ms']:.4f} ms, B={cluster_results['node_b_mean_ms']:.4f} ms, C={cluster_results['node_c_mean_ms']:.4f} ms")

    print("\n[5/6] Benchmarking Authenticated Hot Backups & Restores...")
    backup_results = benchmark_backup_and_restore()
    print(f"      Backup Creation (AES-256-GCM + HMAC): {backup_results['backup_creation_mean_ms']:.2f} ms")
    print(f"      Anti-Rollback Verification & Restore: {backup_results['backup_restore_mean_ms']:.2f} ms")

    print("\n[6/6] Benchmarking Cryptographic Audit Chaining & Verification...")
    audit_results = benchmark_audit_chain()
    for scale, data in audit_results.items():
        print(f"      {scale}: Logging = {data['logging_total_ms']:.2f} ms | Verification = {data['full_verification_ms']:.2f} ms ({data['verification_per_event_ms']:.4f} ms/event)")

    full_benchmarks = {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "phase": "1.2",
        "system": {
            "platform": sys.platform,
            "python_version": sys.version.split()[0]
        },
        "device_authentication": device_auth_results,
        "account_recovery": recovery_results,
        "key_rotation": rotation_results,
        "distributed_propagation": cluster_results,
        "backup_and_restore": backup_results,
        "audit_integrity": audit_results,
    }

    evidence_dir = Path("evidence/phase-1.2")
    evidence_dir.mkdir(parents=True, exist_ok=True)

    json_path = evidence_dir / "performance_benchmarks.json"
    json_path.write_text(json.dumps(full_benchmarks, indent=2), encoding="utf-8")

    txt_path = evidence_dir / "performance_benchmarks.txt"
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("QUANTUMVAULT PHASE 1.2 EMPIRICAL PERFORMANCE BENCHMARKS\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Timestamp: {full_benchmarks['timestamp_utc']}\n")
        f.write(f"Python: {full_benchmarks['system']['python_version']} ({full_benchmarks['system']['platform']})\n\n")

        f.write("1. DEVICE AUTHENTICATION & PROOF-OF-POSSESSION (Ed25519)\n")
        f.write(f"   Keypair Generation: {device_auth_results['key_generation_mean_ms']:.4f} ms (p95: {device_auth_results['key_generation_p95_ms']:.4f} ms)\n")
        f.write(f"   Challenge-Response Verification: {device_auth_results['challenge_response_roundtrip_mean_ms']:.4f} ms (p95: {device_auth_results['challenge_response_roundtrip_p95_ms']:.4f} ms)\n\n")

        f.write("2. ACCOUNT RECOVERY CREDENTIALS\n")
        f.write(f"   Generate 5 High-Entropy Salted Codes: {recovery_results['code_generation_5x_mean_ms']:.4f} ms\n")
        f.write(f"   Atomic Code Verification & Consumption: {recovery_results['code_consumption_mean_ms']:.4f} ms (p95: {recovery_results['code_consumption_p95_ms']:.4f} ms)\n\n")

        f.write("3. KEY ROTATION & ASSET REWRAPPING\n")
        for scale, data in rotation_results.items():
            f.write(f"   {scale}: Total = {data['total_rotation_time_ms']:.2f} ms | Per-Asset = {data['per_asset_rewrap_time_ms']:.4f} ms\n")
        f.write("\n")

        f.write("4. MULTI-NODE CLUSTER PROPAGATION (Nodes A, B, C)\n")
        f.write(f"   Total Propagation: {cluster_results['total_propagation_mean_ms']:.4f} ms (p95: {cluster_results['total_propagation_p95_ms']:.4f} ms)\n")
        f.write(f"   Node A Delivery: {cluster_results['node_a_mean_ms']:.4f} ms\n")
        f.write(f"   Node B Delivery: {cluster_results['node_b_mean_ms']:.4f} ms\n")
        f.write(f"   Node C Delivery: {cluster_results['node_c_mean_ms']:.4f} ms\n\n")

        f.write("5. AUTHENTICATED HOT BACKUPS & RESTORES (AES-256-GCM + HMAC)\n")
        f.write(f"   Backup Creation: {backup_results['backup_creation_mean_ms']:.2f} ms (p95: {backup_results['backup_creation_p95_ms']:.2f} ms)\n")
        f.write(f"   Anti-Rollback Verification & Restore: {backup_results['backup_restore_mean_ms']:.2f} ms (p95: {backup_results['backup_restore_p95_ms']:.2f} ms)\n")
        f.write(f"   Backup Archive Size: {backup_results['backup_size_bytes']} bytes\n\n")

        f.write("6. CRYPTOGRAPHIC AUDIT LOG INTEGRITY\n")
        for scale, data in audit_results.items():
            f.write(f"   {scale}: Logging = {data['logging_total_ms']:.2f} ms | Full Verification = {data['full_verification_ms']:.2f} ms ({data['verification_per_event_ms']:.4f} ms/event)\n")

    print(f"\n[OK] Benchmark evidence saved to {json_path} and {txt_path}\n")
    return full_benchmarks


if __name__ == "__main__":
    run_all_benchmarks()
