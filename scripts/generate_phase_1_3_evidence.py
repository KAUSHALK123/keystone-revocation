"""Comprehensive evidence and benchmark generator for QuantumVault Phase 1.3."""
import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import statistics
import subprocess
import sys
import time
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from quantumvault.crypto.pqc_dsa import MLDSA65
from quantumvault.detection.engine import DetectionEngine
from quantumvault.detection.evaluator import DetectionEvaluator
from quantumvault.detection.ingestion import (
    load_approvals_from_json,
    load_events_from_csv,
    load_labels_from_csv,
)
from quantumvault.iam.authentication import generate_device_keypair
from quantumvault.messaging.e2ee import MessageCipher
from quantumvault.messaging.forward_secrecy import ForwardSecrecyHarness
from quantumvault.messaging.handshake import MessagingHandshake
from quantumvault.messaging.replay import ReplayProtector
from quantumvault.messaging.transport import ChunkedTransport
from quantumvault.testing.lab import SecurityLab
from quantumvault.testing.phase_1_3_combined_scenario import Phase13CombinedScenario


def generate_all_evidence():
    out_dir = ROOT_DIR / "evidence" / "phase-1.3"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"Generating Phase 1.3 Evidence in: {out_dir}")

    # 1. Run Official Validator and record clean output
    print("-> Running Official Validator...")
    val_proc = subprocess.run(
        [sys.executable, str(ROOT_DIR / "references" / "track4-toolkit" / "validate.py"), "--entry", "track4_service.py"],
        capture_output=True,
        text=True,
        cwd=str(ROOT_DIR)
    )
    val_log_path = out_dir / "validator_run.txt"
    with open(val_log_path, "w", encoding="utf-8") as f:
        f.write("QUANTUMVAULT OFFICIAL VALIDATOR RUN (Track 4: Trust, but verify)\n")
        f.write("=" * 70 + "\n")
        f.write(f"Timestamp: {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"Exit Code: {val_proc.returncode}\n\n")
        f.write("STDOUT:\n" + val_proc.stdout + "\n")
        if val_proc.stderr:
            f.write("STDERR:\n" + val_proc.stderr + "\n")

    # 2. Practice Evaluation and Incidents
    print("-> Evaluating Practice Dataset...")
    events = load_events_from_csv(ROOT_DIR / "references" / "track4-toolkit" / "practice" / "events.csv")
    labels = load_labels_from_csv(ROOT_DIR / "references" / "track4-toolkit" / "practice" / "labels.csv")
    approvals = load_approvals_from_json(ROOT_DIR / "references" / "track4-toolkit" / "practice" / "approvals.json")
    
    det_engine = DetectionEngine(approval_registry=approvals)
    classifications = det_engine.evaluate_events(events)
    evaluator = DetectionEvaluator(labels)
    metrics = evaluator.evaluate(classifications)

    eval_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_events": metrics.total_events,
        "exact_matches": metrics.exact_matches,
        "exact_accuracy": metrics.exact_accuracy,
        "precision": metrics.precision,
        "recall": metrics.recall,
        "f1_score": metrics.f1_score,
        "true_positives": metrics.true_positives,
        "false_positives": metrics.false_positives,
        "true_negatives": metrics.true_negatives,
        "false_negatives": metrics.false_negatives,
        "median_time_to_alert_ms": metrics.median_time_to_alert_ms,
        "confusion_matrix": metrics.confusion_matrix,
        "event_classifications": [
            {
                "event_id": c.event_id,
                "predicted_label": c.label,
                "ground_truth_label": labels[c.event_id]["label"],
                "is_match": c.label == labels[c.event_id]["label"],
                "reason": c.reason,
                "rule_id": c.rule_id,
                "incident_id": c.incident_id,
                "is_suspicious": c.is_suspicious,
                "latency_ms": c.latency_ms
            }
            for c in classifications
        ]
    }
    with open(out_dir / "practice_evaluation_results.json", "w", encoding="utf-8") as f:
        json.dump(eval_data, f, indent=2)

    incidents_data = [
        {
            "incident_id": inc.incident_id,
            "rule_id": inc.rule_id,
            "incident_type": inc.incident_type,
            "actor_id": inc.actor_id,
            "severity": inc.severity,
            "explanation": inc.explanation,
            "evidence_event_ids": inc.evidence_event_ids,
            "created_at": inc.created_at
        }
        for inc in det_engine.get_incidents()
    ]
    with open(out_dir / "practice_incidents.json", "w", encoding="utf-8") as f:
        json.dump(incidents_data, f, indent=2)

    # 3. Post-Compromise Forward Secrecy Proof
    print("-> Running Forward Secrecy Harness...")
    fs_harness = ForwardSecrecyHarness()
    fs_proof = fs_harness.run_compromise_simulation()
    fs_proof["timestamp"] = datetime.now(timezone.utc).isoformat()
    fs_proof["mathematical_basis"] = (
        "Post-quantum forward secrecy is guaranteed by ephemeral ML-KEM-768 session establishment. "
        "The ephemeral secret key exists only in volatile memory during decapsulation and is zeroized "
        "immediately thereafter. Even with full exposure of long-term identity keys (Ed25519 / ML-DSA-65), "
        "the hardness of the Module Learning With Errors (M-LWE) problem prevents recovering the shared secret."
    )
    with open(out_dir / "forward_secrecy_proof.json", "w", encoding="utf-8") as f:
        json.dump(fs_proof, f, indent=2)

    # 4. Security Laboratory Scenarios
    print("-> Running 40 Laboratory Scenarios...")
    lab = SecurityLab()
    lab_results = lab.run_all()
    with open(out_dir / "lab_scenarios_results.json", "w", encoding="utf-8") as f:
        json.dump(lab_results, f, indent=2)

    # 5. 40-Step Combined Scenario
    print("-> Running 40-Step Combined Grand Scenario...")
    combined = Phase13CombinedScenario()
    comb_res = combined.run()
    comb_log_path = out_dir / "forty_step_scenario_log.txt"
    with open(comb_log_path, "w", encoding="utf-8") as f:
        f.write("QUANTUMVAULT 40-STEP COMBINED SECURITY RESILIENCE DEMONSTRATION LOG\n")
        f.write("=" * 70 + "\n")
        f.write(f"Timestamp: {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"Result: {comb_res.steps_passed}/{comb_res.total_steps} PASS in {comb_res.execution_time_ms:.1f}ms\n\n")
        for step in comb_res.step_details:
            f.write(f"Step {step['step']:02d}: [{step['status']}] {step['title']}\n")
            f.write(f"  Details: {json.dumps(step['details'])}\n\n")

    # 6. Comprehensive Benchmarks
    print("-> Executing Micro-Benchmarks...")
    benchmarks = run_micro_benchmarks(events, approvals)
    with open(out_dir / "benchmark_results.json", "w", encoding="utf-8") as f:
        json.dump(benchmarks, f, indent=2)

    summary_path = out_dir / "benchmark_summary.txt"
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("QUANTUMVAULT PHASE 1.3 PERFORMANCE BENCHMARK SUMMARY\n")
        f.write("=" * 70 + "\n")
        f.write(f"Timestamp: {datetime.now(timezone.utc).isoformat()}\n\n")
        f.write(f"1. Threat Detection Throughput:    {benchmarks['detection']['throughput_events_per_sec']:.1f} events/sec\n")
        f.write(f"   Median Detection Latency:        {benchmarks['detection']['median_latency_us']:.2f} microseconds\n")
        f.write(f"   p99 Detection Latency:           {benchmarks['detection']['p99_latency_us']:.2f} microseconds\n\n")
        f.write(f"2. PQC Messaging Handshake Latency: {benchmarks['messaging_handshake']['median_handshake_ms']:.3f} ms\n")
        f.write(f"   PQC KEM (ML-KEM-768) Encap:      {benchmarks['messaging_handshake']['median_kem_encap_ms']:.3f} ms\n")
        f.write(f"   PQC KEM (ML-KEM-768) Decap:      {benchmarks['messaging_handshake']['median_kem_decap_ms']:.3f} ms\n")
        f.write(f"   PQC Signature (ML-DSA-65) Sign:  {benchmarks['messaging_handshake']['median_dsa_sign_ms']:.3f} ms\n")
        f.write(f"   PQC Signature (ML-DSA-65) Verify:{benchmarks['messaging_handshake']['median_dsa_verify_ms']:.3f} ms\n\n")
        f.write(f"3. Messaging AEAD Encryption:       {benchmarks['messaging_aead']['encrypt_throughput_mb_sec']:.2f} MB/s\n")
        f.write(f"   Messaging AEAD Decryption:       {benchmarks['messaging_aead']['decrypt_throughput_mb_sec']:.2f} MB/s\n\n")
        f.write(f"4. Replay Check Latency:            {benchmarks['replay_protection']['median_check_us']:.2f} microseconds\n\n")
        f.write(f"5. Chunked Transport Reassembly:    {benchmarks['transport_reassembly']['throughput_mb_sec']:.2f} MB/s\n\n")
        f.write(f"6. 40-Step Combined Scenario Time:  {comb_res.execution_time_ms:.1f} ms\n")
        f.write(f"7. Security Lab 40 Scenarios Time:  {lab_results['total_time_ms']:.1f} ms\n")

    print("Evidence generation completed successfully!")


def run_micro_benchmarks(events, approvals) -> dict[str, Any]:
    # 1. Detection throughput & latency
    det_engine = DetectionEngine(approval_registry=approvals)
    latencies_us: list[float] = []
    iterations = 50
    t0 = time.perf_counter()
    for _ in range(iterations):
        for e in events:
            t_evt = time.perf_counter()
            det_engine.evaluate_events([e])
            latencies_us.append((time.perf_counter() - t_evt) * 1_000_000.0)
    total_det_sec = time.perf_counter() - t0
    total_evts = iterations * len(events)
    latencies_us.sort()

    # 2. PQC Messaging Handshake & Cryptography
    hs = MessagingHandshake()
    dsa = MLDSA65()
    pk_dsa, sk_dsa = dsa.generate_keypair()
    pk_dsa_b64 = dsa.encode_public_key(pk_dsa)

    handshake_latencies: list[float] = []
    kem_encap_latencies: list[float] = []
    kem_decap_latencies: list[float] = []
    dsa_sign_latencies: list[float] = []
    dsa_verify_latencies: list[float] = []

    for _ in range(100):
        # KEM Encap/Decap
        pk_kem, sk_kem = hs.pqc_kem.generate_keypair()
        t_encap = time.perf_counter()
        ct, ss = hs.pqc_kem.encapsulate(pk_kem)
        kem_encap_latencies.append((time.perf_counter() - t_encap) * 1000.0)

        t_decap = time.perf_counter()
        ss_dec = hs.pqc_kem.decapsulate(sk_kem, ct)
        kem_decap_latencies.append((time.perf_counter() - t_decap) * 1000.0)

        # DSA Sign/Verify
        t_dsa_s = time.perf_counter()
        sig = dsa.sign(sk_dsa, b"benchmark-message")
        dsa_sign_latencies.append((time.perf_counter() - t_dsa_s) * 1000.0)

        t_dsa_v = time.perf_counter()
        dsa.verify(pk_dsa, b"benchmark-message", sig)
        dsa_verify_latencies.append((time.perf_counter() - t_dsa_v) * 1000.0)

        # End-to-end handshake
        t_hs = time.perf_counter()
        offer = hs.generate_responder_offer("bob", "dev-b", sk_dsa)
        init_p, _, _ = hs.initiate_session("alice", "dev-a", sk_dsa, offer, pk_dsa_b64)
        hs.complete_responder(offer, init_p, pk_dsa_b64)
        handshake_latencies.append((time.perf_counter() - t_hs) * 1000.0)

    # 3. Messaging AEAD
    cipher = MessageCipher(b"K" * 32, "sess-bench", "alice", "dev-a", "bob", "dev-b")
    payload = b"Q" * 1024 * 10  # 10 KB
    rounds = 1000
    t_enc = time.perf_counter()
    envelopes = [cipher.encrypt_message(payload, i + 1) for i in range(rounds)]
    enc_time = time.perf_counter() - t_enc
    enc_mb_sec = (len(payload) * rounds) / (1024 * 1024 * enc_time)

    t_dec = time.perf_counter()
    for env in envelopes:
        cipher.decrypt_message(env)
    dec_time = time.perf_counter() - t_dec
    dec_mb_sec = (len(payload) * rounds) / (1024 * 1024 * dec_time)

    # 4. Replay protection
    rp = ReplayProtector(window_size=128)
    rp_latencies_us: list[float] = []
    for i in range(1, 2000):
        t_rp = time.perf_counter()
        rp.check_and_record(f"msg-{i}", "sess", i)
        rp_latencies_us.append((time.perf_counter() - t_rp) * 1_000_000.0)

    # 5. Chunked transport reassembly
    transport = ChunkedTransport(chunk_size=1024)
    big_payload = b"B" * 1024 * 500  # 500 KB
    chunks = transport.segment_payload("big-msg", big_payload)
    t_trans = time.perf_counter()
    transport.reassemble(chunks)
    trans_time = time.perf_counter() - t_trans
    trans_mb_sec = len(big_payload) / (1024 * 1024 * trans_time)

    return {
        "detection": {
            "total_events_tested": total_evts,
            "throughput_events_per_sec": total_evts / total_det_sec,
            "median_latency_us": statistics.median(latencies_us),
            "p95_latency_us": latencies_us[int(len(latencies_us) * 0.95)],
            "p99_latency_us": latencies_us[int(len(latencies_us) * 0.99)],
        },
        "messaging_handshake": {
            "median_handshake_ms": statistics.median(handshake_latencies),
            "median_kem_encap_ms": statistics.median(kem_encap_latencies),
            "median_kem_decap_ms": statistics.median(kem_decap_latencies),
            "median_dsa_sign_ms": statistics.median(dsa_sign_latencies),
            "median_dsa_verify_ms": statistics.median(dsa_verify_latencies),
        },
        "messaging_aead": {
            "payload_bytes": len(payload),
            "encrypt_throughput_mb_sec": enc_mb_sec,
            "decrypt_throughput_mb_sec": dec_mb_sec,
        },
        "replay_protection": {
            "median_check_us": statistics.median(rp_latencies_us),
        },
        "transport_reassembly": {
            "payload_size_kb": len(big_payload) / 1024,
            "throughput_mb_sec": trans_mb_sec,
        }
    }


if __name__ == "__main__":
    generate_all_evidence()
