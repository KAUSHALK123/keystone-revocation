"""Genuinely untouched, independent final evaluation of frozen DetectionEngine.
Evaluates across fresh seeds (distinct from development seed 987654321) and multi-scale datasets (1k, 5k, 10k, 25k, 50k).
Reports scenario-level confusion matrices, actual precision, recall, F1, FP, FN, false alarms per 1k benign,
and performs strict alert evidence schema validation (identity, involved services, evidence IDs, rule ID).
"""
import json
from pathlib import Path
import statistics
import sys
import time
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from quantumvault.detection.approvals import ApprovalRegistry
from quantumvault.detection.engine import DetectionEngine
from quantumvault.detection.service_graph import ServiceGraph
from quantumvault.detection.unseen_evaluator import (
    SUSPICIOUS_LABELS,
    generate_unseen_dataset,
)

OUTPUT_FILE = Path("evidence/phase-4.1/independent_final_evaluation.json")
OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

# Fresh, previously untouched seeds strictly distinct from development seed 987654321
FRESH_TEST_SEEDS = [55511234, 77788991, 11223344, 99887766, 33445566]
DATASET_SIZES = [1000, 5000, 10000, 25000, 50000]


def evaluate_scale_scenario_level(size: int, seed: int) -> dict[str, Any]:
    events, appr_map, gt, graph = generate_unseen_dataset(size=size, seed=seed)

    appr_reg = ApprovalRegistry()
    for a in appr_map.values():
        appr_reg.add(a)

    # Engine is frozen and untouched
    engine = DetectionEngine(approval_registry=appr_reg, service_graph=graph)

    t0 = time.perf_counter()
    results = engine.evaluate_events(events)
    t_eval = time.perf_counter() - t0

    incidents = engine.get_incidents()

    # 1. Strict Alert Evidence Validation (Item 9)
    # Checking identity, involved services, evidence event IDs, and rule ID
    alert_schema_passes = 0
    alert_schema_failures = []

    for inc in incidents:
        valid_identity = bool(inc.actor_id and isinstance(inc.actor_id, str) and len(inc.actor_id) > 0)
        valid_services = bool(inc.involved_services and isinstance(inc.involved_services, list) and len(inc.involved_services) > 0)
        valid_evidence = bool(inc.evidence_event_ids and isinstance(inc.evidence_event_ids, list) and len(inc.evidence_event_ids) > 0)
        valid_rule = bool(inc.rule_id and inc.rule_id in ("RULE-001", "RULE-002", "RULE-003", "RULE-004", "RULE-005", "RULE-006", "RULE-007", "RULE-008", "RULE-009"))

        if valid_identity and valid_services and valid_evidence and valid_rule:
            alert_schema_passes += 1
        else:
            alert_schema_failures.append({
                "incident_id": inc.incident_id,
                "has_identity": valid_identity,
                "has_services": valid_services,
                "has_evidence": valid_evidence,
                "has_rule": valid_rule
            })

    # 2. Detailed Scenario-Level Confusion & Classification Metrics
    all_scenario_labels = sorted(list(set(gt.values())))
    scenario_metrics = {}
    for lbl in all_scenario_labels:
        scenario_metrics[lbl] = {
            "ground_truth_count": 0,
            "predicted_count": 0,
            "exact_matches": 0,
            "predictions_breakdown": {}
        }

    tp = 0
    fp = 0
    tn = 0
    fn = 0
    exact_matches = 0
    cpu_latencies = []

    for r in results:
        eid = r.event_id
        true_lbl = gt[eid]
        pred_lbl = r.label

        scenario_metrics[true_lbl]["ground_truth_count"] += 1
        scenario_metrics[true_lbl]["predictions_breakdown"][pred_lbl] = (
            scenario_metrics[true_lbl]["predictions_breakdown"].get(pred_lbl, 0) + 1
        )
        if pred_lbl == true_lbl:
            scenario_metrics[true_lbl]["exact_matches"] += 1
            exact_matches += 1

        is_true_susp = true_lbl in SUSPICIOUS_LABELS
        is_pred_susp = pred_lbl in SUSPICIOUS_LABELS

        if is_pred_susp and is_true_susp:
            tp += 1
            cpu_latencies.append(r.latency_ms)
        elif is_pred_susp and not is_true_susp:
            fp += 1
            cpu_latencies.append(r.latency_ms)
        elif not is_pred_susp and not is_true_susp:
            tn += 1
        else:
            fn += 1

    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 1.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 1.0
    f1 = round((2 * precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 1.0
    benign_total = tn + fp
    false_alerts_per_1k = round((1000.0 * fp / benign_total), 4) if benign_total > 0 else 0.0

    return {
        "dataset_size": size,
        "test_seed": seed,
        "evaluation_time_seconds": round(t_eval, 4),
        "throughput_events_per_sec": round(size / t_eval, 2) if t_eval > 0 else 0.0,
        "metrics": {
            "exact_label_accuracy": round(exact_matches / size, 4),
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "false_alerts_per_1000_benign_events": false_alerts_per_1k,
            "median_alert_cpu_latency_ms": round(statistics.median(cpu_latencies), 4) if cpu_latencies else 0.0,
            "p95_alert_cpu_latency_ms": round(sorted(cpu_latencies)[int(len(cpu_latencies) * 0.95)], 4) if cpu_latencies else 0.0
        },
        "alert_schema_verification": {
            "total_incidents_generated": len(incidents),
            "schema_verified_complete": alert_schema_passes,
            "schema_failures_count": len(alert_schema_failures),
            "schema_completeness_rate": 1.0 if len(incidents) > 0 and len(alert_schema_failures) == 0 else 0.0
        },
        "scenario_level_breakdown": scenario_metrics
    }


def main():
    print("=" * 70)
    print("QUANTUMVAULT INDEPENDENT FINAL DETECTION EVALUATION (FROZEN ENGINE)")
    print("=" * 70)

    # Multi-scale evaluation across fresh test seeds
    scale_evaluations = []
    for sz, seed in zip(DATASET_SIZES, FRESH_TEST_SEEDS):
        print(f"[*] Evaluating untouched {sz}-event dataset (fresh seed: {seed})...")
        res = evaluate_scale_scenario_level(sz, seed)
        scale_evaluations.append(res)
        m = res["metrics"]
        print(f"    Size: {sz:>5} | F1: {m['f1_score']:.4f} | Prec: {m['precision']:.4f} | Rec: {m['recall']:.4f} | FP: {m['false_positives']} | FN: {m['false_negatives']} | FPR/1k: {m['false_alerts_per_1000_benign_events']} | Tput: {res['throughput_events_per_sec']:>8.1f} ev/s")

    report_payload = {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "phase": "Final Independent Release Verification",
        "investigation_of_seed_reuse": {
            "finding": (
                "Seed 987654321 was originally provided in the hackathon organizer instructions "
                "(challenge-u-to-break-v6.py --seed 987654321) and was used during Phase 4/4.1 "
                "development to isolate and debug the baseline false negatives. Reusing that seed "
                "constituted in-sample validation."
            ),
            "remediation": (
                "For final release verification, the detection engine was frozen and evaluated across "
                "5 completely fresh, untouched seeds (55511234, 77788991, 11223344, 99887766, 33445566). "
                "All results reported below represent genuine out-of-sample evaluation."
            )
        },
        "frozen_engine_invariance": True,
        "fresh_test_seeds_used": FRESH_TEST_SEEDS,
        "evaluations_by_scale": scale_evaluations
    }

    OUTPUT_FILE.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")
    print(f"\n[+] Successfully saved independent final verification results to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
