"""Phase 3 Large-Scale Detection Generalization, Cold/Warm Profiling & Multi-Process Benchmark Script.

Produces strictly measured backend metrics under `evidence/phase-3/`.
Uses linear interpolation percentile calculation over sorted latencies:
  p(q) = sorted_vals[idx_lo] * (1 - frac) + sorted_vals[idx_hi] * frac
where pos = (q / 100.0) * (n - 1).
"""
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time
import tracemalloc
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from quantumvault.core.service import QuantumVaultService
from quantumvault.detection.engine import DetectionEngine
from quantumvault.detection.evaluator import DetectionEvaluator
from quantumvault.detection.synthetic_generator import generate_synthetic_dataset
from quantumvault.distributed.multiprocess_cluster import MultiProcessCluster
from quantumvault.iam.authentication import generate_device_keypair
from quantumvault.messaging.handshake import MessagingHandshake

PHASE3_DIR = ROOT_DIR / "evidence" / "phase-3"


def percentile_linear(sorted_vals: list[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return round(sorted_vals[0], 4)
    pos = (pct / 100.0) * (len(sorted_vals) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = pos - lo
    return round(sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac, 4)


def stats_summary(samples_ms: list[float]) -> dict[str, Any]:
    s = sorted(samples_ms)
    n = len(s)
    return {
        "samples": n,
        "percentile_method": "linear_interpolation",
        "median_ms": percentile_linear(s, 50.0),
        "p95_ms": percentile_linear(s, 95.0),
        "p99_ms": percentile_linear(s, 99.0),
        "max_ms": round(s[-1], 4) if s else 0.0,
        "note": "small_sample_tail" if n < 30 else "robust",
    }


def run_detection_scale_evaluation() -> dict[str, Any]:
    cohorts = [
        {"split": "dev", "seed": 301, "target": 100},
        {"split": "dev", "seed": 302, "target": 1000},
        {"split": "held_out", "seed": 901, "target": 100},
        {"split": "held_out", "seed": 902, "target": 1000},
        {"split": "held_out", "seed": 903, "target": 10000},
        {"split": "held_out", "seed": 904, "target": 50000},
    ]
    results = []
    for cfg in cohorts:
        events, registry, labels = generate_synthetic_dataset(
            target_events=cfg["target"],
            seed=cfg["seed"],
        )
        tracemalloc.start()
        t0 = time.perf_counter()
        engine = DetectionEngine(approval_registry=registry)
        preds = engine.evaluate_events(events)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        _, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        ev_res = DetectionEvaluator(labels).evaluate(preds)
        pred_map = {p.event_id: p.label for p in preds}
        # Compute per-class metrics over distinct evaluated classes
        all_classes = sorted({v["label"] for v in labels.values()} | set(pred_map.values()))
        per_class: dict[str, dict[str, Any]] = {}
        for cls_name in all_classes:
            tp = sum(1 for eid, gt_row in labels.items() if gt_row["label"] == cls_name and pred_map.get(eid) == cls_name)
            fp = sum(1 for eid, gt_row in labels.items() if gt_row["label"] != cls_name and pred_map.get(eid) == cls_name)
            fn = sum(1 for eid, gt_row in labels.items() if gt_row["label"] == cls_name and pred_map.get(eid) != cls_name)
            prec = round(tp / (tp + fp), 4) if (tp + fp) else 1.0
            rec = round(tp / (tp + fn), 4) if (tp + fn) else 1.0
            f1 = round((2 * prec * rec) / (prec + rec), 4) if (prec + rec) else 0.0
            per_class[cls_name] = {"support": tp + fn, "tp": tp, "fp": fp, "fn": fn, "precision": prec, "recall": rec, "f1": f1}

        throughput = round(len(events) / max(elapsed_ms / 1000.0, 1e-6), 1)
        results.append({
            "split": cfg["split"],
            "seed": cfg["seed"],
            "target_events": cfg["target"],
            "actual_events": len(events),
            "exact_accuracy": ev_res.exact_accuracy,
            "precision": ev_res.precision,
            "recall": ev_res.recall,
            "f1_score": ev_res.f1_score,
            "false_positives": ev_res.false_positives,
            "false_negatives": ev_res.false_negatives,
            "processing_latency_ms": round(elapsed_ms, 2),
            "throughput_events_per_sec": throughput,
            "peak_memory_mib": round(peak_bytes / (1024 * 1024), 2),
            "confusion_matrix": ev_res.confusion_matrix,
            "per_class": per_class,
        })
    return {"cohorts": results}


def run_adapter_and_crypto_benchmarks() -> dict[str, Any]:
    results: dict[str, Any] = {}
    with tempfile.TemporaryDirectory() as td:
        env = os.environ.copy()
        env["TRACK4_STATE_DIR"] = td

        def call_adapter(payload: dict[str, Any]) -> float:
            t0 = time.perf_counter()
            proc = subprocess.Popen(
                [sys.executable, "-B", str(ROOT_DIR / "track4_service.py")],
                cwd=str(ROOT_DIR),
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            proc.communicate(json.dumps(payload).encode("utf-8"), timeout=10.0)
            return (time.perf_counter() - t0) * 1000.0

        # Cold-first setup + warm subprocess reads (n=30)
        cold_setup_ms = call_adapter({
            "op": "setup",
            "owners": {"doc-p3": "alice"},
            "contents": {"doc-p3": "Phase 3 Latency Payload"},
            "disabled": [],
            "key_material": "p3-bench-seed",
        })
        cold_first_read_ms = call_adapter({"op": "read", "actor": "alice", "asset": "doc-p3", "request_id": "cold-read-0"})

        warm_reads: list[float] = []
        for i in range(30):
            warm_reads.append(call_adapter({"op": "read", "actor": "alice", "asset": "doc-p3", "request_id": f"warm-read-{i}"}))

        results["adapter_cold_setup_ms"] = round(cold_setup_ms, 4)
        results["adapter_cold_first_read_ms"] = round(cold_first_read_ms, 4)
        results["adapter_subprocess_read_warm"] = stats_summary(warm_reads)

        # In-process service reads (n=200)
        svc = QuantumVaultService(state_dir=Path(td))
        try:
            allow_times: list[float] = []
            deny_times: list[float] = []
            for i in range(200):
                t0 = time.perf_counter()
                svc.read("alice", "doc-p3", f"svc-allow-{i}")
                allow_times.append((time.perf_counter() - t0) * 1000.0)
                t1 = time.perf_counter()
                svc.read("eve", "doc-p3", f"svc-deny-{i}")
                deny_times.append((time.perf_counter() - t1) * 1000.0)
            results["authorized_read"] = stats_summary(allow_times)
            results["unauthorized_read"] = stats_summary(deny_times)
        finally:
            svc.close()

        # PQC ML-KEM-768 handshake (n=50)
        hs = MessagingHandshake()
        sk_a, pk_a = generate_device_keypair()
        sk_b, pk_b = generate_device_keypair()
        hs_times: list[float] = []
        for _ in range(50):
            t0 = time.perf_counter()
            offer = hs.generate_responder_offer("bob", "db", sk_b)
            init_p, _, _ = hs.initiate_session("alice", "da", sk_a, offer, pk_b)
            hs.complete_responder(offer, init_p, pk_a)
            hs_times.append((time.perf_counter() - t0) * 1000.0)
        results["pqc_handshake_mlkem768_mldsa65"] = stats_summary(hs_times)

    return {
        "environment": {
            "os": platform.platform(),
            "processor": platform.processor(),
            "cpu_count": os.cpu_count(),
            "python_version": platform.python_version(),
        },
        "benchmarks": results,
    }


def run_multiprocess_cluster_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as td:
        cluster = MultiProcessCluster(Path(td))
        try:
            cluster.setup_all(
                owners={"doc": "alice", "probe-asset": "bob"},
                contents={"doc": "MP Secret", "probe-asset": "Probe"},
                disabled=[],
                key_material="mp-bench-seed",
            )
            commit_times: list[float] = []
            prop_times: list[float] = []
            probe_times: list[float] = []
            for i in range(15):
                res = cluster.broadcast_revocation(f"rev-target-{i}", reason="bench")
                commit_times.append(res["auth_commit_latency_ms"])
                prop_times.append(res["total_propagation_ms"])
                valid_probes = [v for v in res["denial_enforcement_latencies_ms"].values() if v >= 0]
                if valid_probes:
                    probe_times.append(max(valid_probes))
            return {
                "cluster_mode": cluster.cluster_mode,
                "nodes": 3,
                "authority_commit_latency": stats_summary(commit_times),
                "total_ipc_propagation_latency": stats_summary(prop_times),
                "denial_enforcement_probe_latency": stats_summary(probe_times),
            }
        finally:
            cluster.close()


def main() -> None:
    PHASE3_DIR.mkdir(parents=True, exist_ok=True)
    print("[1/3] Running multi-seed detection scalability evaluation (up to 50,000 events)...")
    det_res = run_detection_scale_evaluation()
    (PHASE3_DIR / "detection_scale_evaluation.json").write_text(json.dumps(det_res, indent=2), encoding="utf-8")

    print("[2/3] Running Phase 3 cold/warm adapter & cryptographic latency benchmarks...")
    bm_res = run_adapter_and_crypto_benchmarks()
    (PHASE3_DIR / "benchmarks_phase3.json").write_text(json.dumps(bm_res, indent=2), encoding="utf-8")

    print("[3/3] Running Independent Multi-Process Local-IPC Cluster benchmarks...")
    mp_res = run_multiprocess_cluster_benchmark()
    (PHASE3_DIR / "multiprocess_cluster_results.json").write_text(json.dumps(mp_res, indent=2), encoding="utf-8")

    lines = ["=== QUANTUMVAULT PHASE 3 ADVERSARIAL EVALUATION & OPTIMIZATION SUMMARY ===", ""]
    lines.append("1. LARGE-SCALE INDEPENDENT DETECTION EVALUATION:")
    for c in det_res["cohorts"]:
        lines.append(
            f"   - [{c['split'].upper():8s}] seed={c['seed']} events={c['actual_events']:5d} | "
            f"Acc={c['exact_accuracy']:.4f} Prec={c['precision']:.4f} Rec={c['recall']:.4f} F1={c['f1_score']:.4f} "
            f"| FP={c['false_positives']} FN={c['false_negatives']} | {c['processing_latency_ms']}ms ({c['throughput_events_per_sec']} evt/s) "
            f"| PeakMem={c['peak_memory_mib']} MiB"
        )
    lines.append("")
    lines.append("2. ADAPTER COLD VS WARM & CORE PERFORMANCE BENCHMARKS:")
    bms = bm_res["benchmarks"]
    lines.append(f"   - adapter_cold_setup_ms           : {bms['adapter_cold_setup_ms']} ms")
    lines.append(f"   - adapter_cold_first_read_ms      : {bms['adapter_cold_first_read_ms']} ms")
    for k in ("adapter_subprocess_read_warm", "authorized_read", "unauthorized_read", "pqc_handshake_mlkem768_mldsa65"):
        v = bms[k]
        lines.append(f"   - {k:32s}: median={v['median_ms']}ms | p95={v['p95_ms']}ms | max={v['max_ms']}ms (n={v['samples']})")
    lines.append("")
    lines.append("3. INDEPENDENT MULTI-PROCESS LOCAL-IPC CLUSTER (3 OS WORKER NODES):")
    lines.append(f"   - authority_commit_latency        : median={mp_res['authority_commit_latency']['median_ms']}ms (n={mp_res['authority_commit_latency']['samples']})")
    lines.append(f"   - total_ipc_propagation_latency   : median={mp_res['total_ipc_propagation_latency']['median_ms']}ms (n={mp_res['total_ipc_propagation_latency']['samples']})")
    lines.append(f"   - denial_enforcement_probe_latency: median={mp_res['denial_enforcement_probe_latency']['median_ms']}ms")

    summary_txt = "\n".join(lines) + "\n"
    (PHASE3_DIR / "phase3_summary.txt").write_text(summary_txt, encoding="utf-8")
    print("\n" + summary_txt)


if __name__ == "__main__":
    main()
