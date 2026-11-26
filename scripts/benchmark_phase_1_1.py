"""Empirical baseline performance benchmark for QuantumVault Phase 1.1."""
import base64
import json
import os
from pathlib import Path
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from quantumvault.core.service import QuantumVaultService
from quantumvault.crypto.encryption import AuthenticatedEncryption
from quantumvault.crypto.hmac_proof import verify_proof
from quantumvault.crypto.pqc_kem import MLKEM768
from quantumvault.storage.db import get_connection, init_db


def benchmark_operation(func, iterations=100) -> dict:
    """Run an operation multiple times and calculate min, median, p95, max in milliseconds."""
    times_ms = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        func()
        t1 = time.perf_counter_ns()
        times_ms.append((t1 - t0) / 1_000_000.0)
    
    times_sorted = sorted(times_ms)
    p95_idx = int(0.95 * len(times_sorted))
    return {
        "sample_count": iterations,
        "min_ms": round(min(times_ms), 4),
        "median_ms": round(statistics.median(times_ms), 4),
        "p95_ms": round(times_sorted[p95_idx], 4),
        "max_ms": round(max(times_ms), 4),
        "mean_ms": round(statistics.mean(times_ms), 4),
        "stdev_ms": round(statistics.stdev(times_ms), 4) if len(times_ms) > 1 else 0.0
    }


def main():
    print("Executing QuantumVault Phase 1.1 Performance Baseline Benchmarks...")
    results = {
        "metadata": {
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
            "python_version": sys.version.split()[0],
            "pqc_library": "pqcrypto==0.4.0 (ML-KEM-768)",
            "cipher_library": "cryptography (AES-256-GCM)",
            "storage_engine": "SQLite 3 (WAL mode)"
        },
        "benchmarks": {}
    }

    # 1. Database Initialization
    def bench_db_init():
        with tempfile.TemporaryDirectory() as td:
            db_file = Path(td) / "bench.db"
            conn = get_connection(db_file)
            init_db(conn)
            conn.close()
    results["benchmarks"]["database_initialization"] = benchmark_operation(bench_db_init, iterations=30)

    # Prepare persistent test service for subsequent operations
    temp_dir = tempfile.TemporaryDirectory()
    state_dir = Path(temp_dir.name)
    service = QuantumVaultService(state_dir=state_dir)
    service.setup(
        owners={"bench-asset-1": "bench-actor-1", "bench-asset-2": "bench-actor-2"},
        contents={"bench-asset-1": "Confidential benchmark payload", "bench-asset-2": "Another payload"},
        disabled=["disabled-actor"],
        key_material="benchmark-key-material-998877"
    )

    # 2. Authorized Read
    req_counter = 0
    def bench_auth_read():
        nonlocal req_counter
        req_counter += 1
        service.read(actor="bench-actor-1", asset="bench-asset-1", request_id=f"r-auth-{req_counter}")
    results["benchmarks"]["authorized_read"] = benchmark_operation(bench_auth_read, iterations=100)

    # 3. Denied Read
    def bench_denied_read():
        nonlocal req_counter
        req_counter += 1
        service.read(actor="wrong-actor", asset="bench-asset-1", request_id=f"r-deny-{req_counter}")
    results["benchmarks"]["denied_read"] = benchmark_operation(bench_denied_read, iterations=100)

    # 4. Actor Revocation
    rev_counter = 0
    def bench_revocation():
        nonlocal rev_counter
        rev_counter += 1
        service.revoke(actor=f"rev-actor-{rev_counter}")
    results["benchmarks"]["actor_revocation"] = benchmark_operation(bench_revocation, iterations=100)

    # 5. Historical Audit Retrieval
    def bench_audit_retrieval():
        service.audit(request_id="r-auth-1")
    results["benchmarks"]["historical_audit_retrieval"] = benchmark_operation(bench_audit_retrieval, iterations=100)

    # 6. ML-KEM Key Generation
    pqc = MLKEM768()
    def bench_pqc_keygen():
        pqc.generate_keypair()
    results["benchmarks"]["ml_kem_768_keygen"] = benchmark_operation(bench_pqc_keygen, iterations=100)

    # 7. ML-KEM Encapsulation
    pk, sk = pqc.generate_keypair()
    def bench_pqc_encaps():
        pqc.encapsulate(pk)
    results["benchmarks"]["ml_kem_768_encapsulation"] = benchmark_operation(bench_pqc_encaps, iterations=100)

    # 8. ML-KEM Decapsulation
    ct, _ = pqc.encapsulate(pk)
    def bench_pqc_decaps():
        pqc.decapsulate(sk, ct)
    results["benchmarks"]["ml_kem_768_decapsulation"] = benchmark_operation(bench_pqc_decaps, iterations=100)

    # 9. Protected Read Full Round-Trip Verification
    b64_pk = base64.b64encode(pk).decode("ascii")
    def bench_protected_read_verification():
        challenge = f"ch-{time.perf_counter_ns()}"
        res = service.protected_read(
            actor="bench-actor-1",
            asset="bench-asset-1",
            challenge=challenge,
            public_key=b64_pk
        )
        ct_bytes = base64.b64decode(res["ciphertext"])
        ss = pqc.decapsulate(sk, ct_bytes)
        verify_proof(res["proof"], ss, challenge, "Confidential benchmark payload")
    results["benchmarks"]["protected_read_full_verification"] = benchmark_operation(bench_protected_read_verification, iterations=100)

    # 10. Resource Encryption (AES-256-GCM)
    key = b"\x42" * 32
    cipher = AuthenticatedEncryption(key)
    sample_text = "Standard benchmark payload for QuantumVault AES-256-GCM authenticated storage."
    def bench_aes_encrypt():
        cipher.encrypt(sample_text)
    results["benchmarks"]["resource_encryption_aes_gcm"] = benchmark_operation(bench_aes_encrypt, iterations=100)

    # 11. Resource Decryption (AES-256-GCM)
    sample_ct, sample_nonce = cipher.encrypt(sample_text)
    def bench_aes_decrypt():
        cipher.decrypt(sample_ct, sample_nonce)
    results["benchmarks"]["resource_decryption_aes_gcm"] = benchmark_operation(bench_aes_decrypt, iterations=100)

    service.close()
    temp_dir.cleanup()

    # Save outputs to evidence directory
    evidence_dir = Path("evidence/phase-1.1")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    json_path = evidence_dir / "performance_benchmarks.json"
    txt_path = evidence_dir / "performance_benchmarks.txt"

    json_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    # Generate human-readable table
    lines = [
        "=" * 80,
        "QUANTUMVAULT PHASE 1.1 PERFORMANCE BENCHMARK REPORT",
        "=" * 80,
        f"Timestamp:       {results['metadata']['timestamp_utc']}",
        f"Operating System:{results['metadata']['os']}",
        f"Python Runtime:  {results['metadata']['python_version']}",
        f"PQC Library:     {results['metadata']['pqc_library']}",
        f"Cipher Library:  {results['metadata']['cipher_library']}",
        f"Storage Engine:  {results['metadata']['storage_engine']}",
        "-" * 80,
        f"{'Operation':<35} | {'Samples':<7} | {'Median (ms)':<11} | {'P95 (ms)':<9} | {'Mean ± Std (ms)'}",
        "-" * 80,
    ]
    for name, data in results["benchmarks"].items():
        mean_std = f"{data['mean_ms']:.3f} ± {data['stdev_ms']:.3f}"
        lines.append(f"{name:<35} | {data['sample_count']:<7} | {data['median_ms']:<11.4f} | {data['p95_ms']:<9.4f} | {mean_std}")
    lines.append("=" * 80)
    
    formatted_report = "\n".join(lines)
    txt_path.write_text(formatted_report, encoding="utf-8")
    print(formatted_report)
    print(f"\nSaved benchmark outputs to {json_path} and {txt_path}")


if __name__ == "__main__":
    main()
