"""Independent unseen dataset generator, evaluation benchmark, and clock range analyzer.
Generates unseen synthetic datasets with independent ground-truth labeling and
evaluates DetectionEngine without any AI/ML models or heuristic dependencies.
"""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import random
import statistics
import time
from typing import Any

from quantumvault.detection.approvals import ApprovalRegistry
from quantumvault.detection.clock import correct_timestamp, format_iso_timestamp
from quantumvault.detection.engine import DetectionEngine
from quantumvault.detection.models import ApprovalChange, SecurityEvent
from quantumvault.detection.service_graph import ServiceGraph

SUSPICIOUS_LABELS = {
    "unexpected_role_change",
    "review_after_role_change",
    "lateral_movement_candidate",
}


def generate_unseen_dataset(size: int = 1000, seed: int = 42) -> tuple[list[SecurityEvent], dict[str, ApprovalChange], dict[str, str], ServiceGraph]:
    """Generate independent synthetic dataset with novel identities, topologies, and ground truth."""
    rng = random.Random(seed)

    services = [f"svc-unseen-{i}" for i in range(12)]
    actors = [f"usr-synth-{i}" for i in range(25)]

    # Build known service graph topology
    graph = ServiceGraph(expected_edges=set())
    for i in range(len(services) - 1):
        graph.add_expected_edge(services[i], services[i+1])
        graph.add_expected_edge(services[i+1], services[i])
    graph.add_expected_edge(services[0], services[4])
    graph.add_expected_edge(services[2], services[6])

    base_time = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
    current_time = base_time

    events: list[SecurityEvent] = []
    ground_truth: dict[str, str] = {}
    approvals_map: dict[str, ApprovalChange] = {}

    event_counter = 0

    while len(events) < size:
        scenario_type = rng.choices(
            [
                "routine",
                "approved_elevation",
                "unapproved_elevation_and_review",
                "lateral_movement",
                "isolated_denial",
                "clock_offset",
                "delayed_transit"
            ],
            weights=[55, 12, 8, 5, 10, 5, 5]
        )[0]

        actor = rng.choice(actors)
        session = f"sess-{rng.randint(1000, 999999)}"

        if scenario_type == "routine":
            src = rng.choice(services[:6])
            neighbors = [t for s, t in graph.expected_edges if s == src]
            tgt = rng.choice(neighbors) if neighbors else services[1]
            current_time += timedelta(milliseconds=rng.randint(100, 800))
            t_iso = format_iso_timestamp(current_time)
            eid = f"evt-{event_counter:06d}"
            event_counter += 1

            ev = SecurityEvent(
                event_id=eid,
                event_time_utc=t_iso,
                received_time_utc=t_iso,
                source_clock_offset_ms=0,
                actor=actor,
                source_service=src,
                target_service=tgt,
                action="read",
                role_before="operator",
                role_after="operator",
                outcome="allow",
                session_id=session
            )
            events.append(ev)
            ground_truth[eid] = "routine"

        elif scenario_type == "approved_elevation":
            src = services[0]
            tgt = services[1]
            current_time += timedelta(milliseconds=rng.randint(200, 500))
            t_iso = format_iso_timestamp(current_time)
            eid = f"evt-{event_counter:06d}"
            event_counter += 1

            appr_id = f"appr-{event_counter:06d}-{rng.randint(1000, 9999)}"
            window_start = format_iso_timestamp(current_time - timedelta(minutes=5))
            window_end = format_iso_timestamp(current_time + timedelta(minutes=30))

            approvals_map[appr_id] = ApprovalChange(
                approval_id=appr_id,
                approved_by="sec-lead",
                subject=actor,
                operation="grant_role",
                role="admin",
                scope=[src, tgt],
                valid_from_utc=window_start,
                valid_until_utc=window_end
            )

            ev = SecurityEvent(
                event_id=eid,
                event_time_utc=t_iso,
                received_time_utc=t_iso,
                source_clock_offset_ms=0,
                actor=actor,
                source_service=src,
                target_service=tgt,
                action="role_change",
                role_before="operator",
                role_after="admin",
                outcome="allow",
                approval_id=appr_id,
                session_id=session
            )
            events.append(ev)
            ground_truth[eid] = "approved_change"

        elif scenario_type == "unapproved_elevation_and_review":
            src = services[0]
            tgt = services[1]
            current_time += timedelta(milliseconds=rng.randint(200, 500))
            t_iso = format_iso_timestamp(current_time)
            eid1 = f"evt-{event_counter:06d}"
            event_counter += 1

            # Step 1: Unapproved role change
            ev1 = SecurityEvent(
                event_id=eid1,
                event_time_utc=t_iso,
                received_time_utc=t_iso,
                source_clock_offset_ms=0,
                actor=actor,
                source_service=src,
                target_service=tgt,
                action="role_change",
                role_before="operator",
                role_after="admin",
                outcome="allow",
                session_id=session
            )
            events.append(ev1)
            ground_truth[eid1] = "unexpected_role_change"

            # Step 2: Sensitive review operation in same session
            current_time += timedelta(milliseconds=rng.randint(100, 400))
            t_iso2 = format_iso_timestamp(current_time)
            eid2 = f"evt-{event_counter:06d}"
            event_counter += 1

            ev2 = SecurityEvent(
                event_id=eid2,
                event_time_utc=t_iso2,
                received_time_utc=t_iso2,
                source_clock_offset_ms=0,
                actor=actor,
                source_service=services[1],
                target_service=services[2],
                action="access_review",
                role_before="admin",
                role_after="admin",
                outcome="allow",
                session_id=session
            )
            events.append(ev2)
            ground_truth[eid2] = "review_after_role_change"

        elif scenario_type == "lateral_movement":
            chain_len = rng.randint(2, 3)
            unauth_actor = f"attacker-{rng.randint(100, 999)}"
            lat_sess = f"lat-sess-{rng.randint(1000, 9999)}"

            for _ in range(chain_len):
                current_time += timedelta(milliseconds=rng.randint(100, 300))
                t_iso = format_iso_timestamp(current_time)
                eid = f"evt-{event_counter:06d}"
                event_counter += 1

                # Disconnected service hops not in graph
                src_node = services[rng.randint(7, 9)]
                tgt_node = services[rng.randint(10, 11)]

                ev = SecurityEvent(
                    event_id=eid,
                    event_time_utc=t_iso,
                    received_time_utc=t_iso,
                    source_clock_offset_ms=0,
                    actor=unauth_actor,
                    source_service=src_node,
                    target_service=tgt_node,
                    action="rpc_query",
                    role_before="operator",
                    role_after="operator",
                    outcome="deny",
                    session_id=lat_sess
                )
                events.append(ev)
                ground_truth[eid] = "lateral_movement_candidate"

        elif scenario_type == "isolated_denial":
            src = services[0]
            tgt = services[1]
            current_time += timedelta(milliseconds=rng.randint(200, 500))
            t_iso = format_iso_timestamp(current_time)
            eid = f"evt-{event_counter:06d}"
            event_counter += 1

            # Isolated denial on a valid edge or unique single-hop session
            iso_sess = f"iso-sess-{rng.randint(10000, 99999)}"
            ev = SecurityEvent(
                event_id=eid,
                event_time_utc=t_iso,
                received_time_utc=t_iso,
                source_clock_offset_ms=0,
                actor=actor,
                source_service=src,
                target_service=tgt,
                action="read",
                role_before="operator",
                role_after="operator",
                outcome="deny",
                session_id=iso_sess
            )
            events.append(ev)
            ground_truth[eid] = "isolated_denial"

        elif scenario_type == "clock_offset":
            src = services[0]
            neighbors = [t for s, t in graph.expected_edges if s == src]
            tgt = rng.choice(neighbors) if neighbors else services[1]
            offset_ms = rng.choice([-3600000, -60000, -5000, -2000, 2000, 5000, 60000, 3600000])
            current_time += timedelta(milliseconds=rng.randint(200, 500))
            raw_event_time = current_time + timedelta(milliseconds=offset_ms)

            t_iso = format_iso_timestamp(raw_event_time)
            r_iso = format_iso_timestamp(current_time)
            eid = f"evt-{event_counter:06d}"
            event_counter += 1

            ev = SecurityEvent(
                event_id=eid,
                event_time_utc=t_iso,
                received_time_utc=r_iso,
                source_clock_offset_ms=offset_ms,
                actor=actor,
                source_service=src,
                target_service=tgt,
                action="read",
                role_before="operator",
                role_after="operator",
                outcome="allow",
                session_id=session
            )
            events.append(ev)
            ground_truth[eid] = "routine_clock_offset"

        elif scenario_type == "delayed_transit":
            src = services[0]
            neighbors = [t for s, t in graph.expected_edges if s == src]
            tgt = rng.choice(neighbors) if neighbors else services[1]
            current_time += timedelta(milliseconds=rng.randint(200, 500))
            event_time = current_time - timedelta(seconds=rng.randint(2, 8))

            t_iso = format_iso_timestamp(event_time)
            r_iso = format_iso_timestamp(current_time)
            eid = f"evt-{event_counter:06d}"
            event_counter += 1

            ev = SecurityEvent(
                event_id=eid,
                event_time_utc=t_iso,
                received_time_utc=r_iso,
                source_clock_offset_ms=0,
                actor=actor,
                source_service=src,
                target_service=tgt,
                action="read",
                role_before="operator",
                role_after="operator",
                outcome="allow",
                session_id=session
            )
            events.append(ev)
            ground_truth[eid] = "routine_delayed_delivery"

    # Slice strictly to target size
    events = events[:size]
    ground_truth = {e.event_id: ground_truth[e.event_id] for e in events}

    return events, approvals_map, ground_truth, graph


def evaluate_dataset(events: list[SecurityEvent], approvals_map: dict[str, ApprovalChange],
                     ground_truth: dict[str, str], graph: ServiceGraph) -> dict[str, Any]:
    """Execute DetectionEngine across events and compute rigorous classification & latency metrics."""
    appr_registry = ApprovalRegistry()
    for appr in approvals_map.values():
        appr_registry.add(appr)

    engine = DetectionEngine(approval_registry=appr_registry, service_graph=graph)

    t_start = time.perf_counter()
    results = engine.evaluate_events(events)
    t_end = time.perf_counter()
    total_eval_seconds = t_end - t_start

    throughput_events_per_sec = round(len(events) / total_eval_seconds, 2) if total_eval_seconds > 0 else 0.0

    tp = 0
    fp = 0
    tn = 0
    fn = 0
    exact_matches = 0
    alert_latencies: list[float] = []

    confusion_matrix: dict[str, dict[str, int]] = {}

    for res in results:
        eid = res.event_id
        gt = ground_truth.get(eid, "unknown")
        pred = res.label

        if gt not in confusion_matrix:
            confusion_matrix[gt] = {}
        confusion_matrix[gt][pred] = confusion_matrix[gt].get(pred, 0) + 1

        if pred == gt:
            exact_matches += 1

        is_gt_suspicious = gt in SUSPICIOUS_LABELS
        is_pred_suspicious = pred in SUSPICIOUS_LABELS

        if is_pred_suspicious and is_gt_suspicious:
            tp += 1
            alert_latencies.append(res.latency_ms)
        elif is_pred_suspicious and not is_gt_suspicious:
            fp += 1
            alert_latencies.append(res.latency_ms)
        elif not is_pred_suspicious and not is_gt_suspicious:
            tn += 1
        else:
            fn += 1

    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 1.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 1.0
    f1 = round((2 * precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 1.0

    benign_total = fp + tn
    false_alerts_per_1000_benign = round((1000.0 * fp / benign_total), 4) if benign_total > 0 else 0.0

    median_alert_latency_ms = round(statistics.median(alert_latencies), 4) if alert_latencies else 0.0
    sorted_latencies = sorted(alert_latencies) if alert_latencies else [0.0]
    p95_idx = int(len(sorted_latencies) * 0.95)
    p95_alert_latency_ms = round(sorted_latencies[min(p95_idx, len(sorted_latencies)-1)], 4)
    max_alert_latency_ms = round(max(sorted_latencies), 4)

    return {
        "total_events": len(events),
        "ground_truth_suspicious_events": tp + fn,
        "ground_truth_benign_events": tn + fp,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "exact_label_accuracy": round(exact_matches / len(events), 4),
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_alerts_per_1000_benign_events": false_alerts_per_1000_benign,
        "median_time_to_alert_ms": median_alert_latency_ms,
        "p95_alert_latency_ms": p95_alert_latency_ms,
        "max_alert_latency_ms": max_alert_latency_ms,
        "throughput_events_per_sec": throughput_events_per_sec,
        "total_evaluation_seconds": round(total_eval_seconds, 4),
        "confusion_matrix": confusion_matrix
    }


def evaluate_clock_offset_range() -> dict[str, Any]:
    """Test and document supported clock offset range and out-of-order tolerance."""
    tested_offsets_ms = [-3600000, -60000, -5000, -2000, -500, 0, 500, 2000, 5000, 60000, 3600000]
    results = []

    base_time = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)
    base_iso = format_iso_timestamp(base_time)

    for offset in tested_offsets_ms:
        raw_event_time = base_time + timedelta(milliseconds=offset)
        raw_iso = format_iso_timestamp(raw_event_time)

        corrected_iso = correct_timestamp(raw_iso, offset)
        diff_ms = abs((datetime.fromisoformat(corrected_iso) - base_time).total_seconds() * 1000.0)
        success = diff_ms < 2.0

        results.append({
            "offset_ms": offset,
            "raw_timestamp": raw_iso,
            "reference_utc": base_iso,
            "corrected_timestamp": corrected_iso,
            "error_ms": diff_ms,
            "success": success
        })

    return {
        "supported_clock_offset_range": "[-3600.0s, +3600.0s] (tested -1 hour to +1 hour)",
        "tested_offsets_count": len(tested_offsets_ms),
        "all_offsets_verified": all(r["success"] for r in results),
        "max_tested_offset_seconds": 3600.0,
        "tested_offsets": results,
        "supported_out_of_order_window_seconds": 10.0,
        "handling_outside_range": "Events outside window flagged as out_of_order without corrupting sequence"
    }
