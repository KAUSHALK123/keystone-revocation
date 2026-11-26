"""Threat detection, practice events playback, synthetic evaluation, and service graph routes."""
from pathlib import Path
import time
from fastapi import APIRouter, Depends, Query
from quantumvault.detection.engine import DetectionEngine
from quantumvault.detection.evaluator import DetectionEvaluator
from quantumvault.detection.ingestion import (
    load_approvals_from_json,
    load_events_from_csv,
    load_labels_from_csv,
)
from quantumvault.web.authentication import verify_operator_auth
from quantumvault.web.schemas import (
    DetectionMetricsResponse,
    IncidentModel,
    PracticeEventModel,
    ServiceGraphEdge,
    ServiceGraphNode,
    ServiceGraphResponse,
    ThreatOverviewResponse,
)

router = APIRouter(prefix="/api/v1/detection", tags=["Threat Radar"])

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
PRACTICE_DIR = ROOT_DIR / "references" / "track4-toolkit" / "practice"


def _get_engine_and_data():
    t0 = time.perf_counter()
    events = load_events_from_csv(PRACTICE_DIR / "events.csv")
    labels = load_labels_from_csv(PRACTICE_DIR / "labels.csv")
    approvals = load_approvals_from_json(PRACTICE_DIR / "approvals.json")
    engine = DetectionEngine(approval_registry=approvals)
    t_eval_start = time.perf_counter()
    classifications = engine.evaluate_events(events)
    eval_elapsed_s = max(time.perf_counter() - t_eval_start, 1e-6)
    throughput_eps = round(len(events) / eval_elapsed_s, 1)
    evaluator = DetectionEvaluator(labels)
    metrics = evaluator.evaluate(classifications)
    return events, labels, approvals, engine, classifications, metrics, throughput_eps


@router.get("/overview", response_model=ThreatOverviewResponse)
def get_threat_overview(auth: dict = Depends(verify_operator_auth)):
    """Return aggregated threat and telemetry overview counts derived from DetectionEngine."""
    events, labels, approvals, engine, classifications, metrics, _ = _get_engine_and_data()

    suspicious_count = sum(1 for c in classifications if c.is_suspicious)
    routine_count = len(classifications) - suspicious_count
    role_changes = sum(1 for c in classifications if c.label == "unexpected_role_change")
    lateral_movements = sum(1 for c in classifications if c.label == "lateral_movement_candidate")
    approved = sum(1 for c in classifications if c.label == "approved_change")
    delayed = sum(1 for c in classifications if c.label == "routine_delayed_delivery")
    offsets = sum(1 for e in events if e.source_clock_offset_ms != 0)

    return ThreatOverviewResponse(
        events_processed=len(events),
        routine_events=routine_count,
        suspicious_events=suspicious_count,
        active_incidents=len(engine.incidents),
        unexpected_role_changes=role_changes,
        lateral_movement_candidates=lateral_movements,
        approved_changes=approved,
        delayed_events=delayed,
        clock_offset_events=offsets,
    )


@router.get("/practice-events", response_model=list[PracticeEventModel])
def get_practice_events(
    actor: str | None = Query(default=None, max_length=128),
    service: str | None = Query(default=None, max_length=128),
    classification: str | None = Query(default=None, max_length=64),
    evaluation_mode: bool = Query(default=True),
    auth: dict = Depends(verify_operator_auth),
):
    """Return official practice events with raw/corrected timestamps and deterministic classifications."""
    events, labels, approvals, engine, classifications, metrics, _ = _get_engine_and_data()

    results: list[PracticeEventModel] = []
    class_map = {c.event_id: c for c in classifications}

    for ev in events:
        c = class_map.get(ev.event_id)
        pred_label = c.label if c else "unknown"
        pred_reason = c.reason if c else ""

        gt_info = labels.get(ev.event_id, {})
        gt_label = gt_info.get("label", "unknown") if evaluation_mode else None

        if actor and ev.actor != actor:
            continue
        if service and ev.source_service != service and ev.target_service != service:
            continue
        if classification and pred_label != classification:
            continue

        results.append(PracticeEventModel(
            event_id=ev.event_id,
            event_time_utc=str(ev.event_time_utc),
            received_time_utc=str(ev.received_time_utc),
            source_clock_offset_ms=ev.source_clock_offset_ms,
            corrected_time_utc=str(ev.corrected_time_utc),
            actor=ev.actor,
            source_service=ev.source_service,
            target_service=ev.target_service,
            action=ev.action,
            role_before=ev.role_before,
            role_after=ev.role_after,
            outcome=ev.outcome,
            approval_id=ev.approval_id,
            session_id=ev.session_id or "",
            correlation_id=ev.correlation_id or "",
            predicted_label=pred_label,
            ground_truth_label=gt_label,
            reason=pred_reason,
            timing_uncertainty_ms=10.0 if ev.source_clock_offset_ms != 0 else 1.0,
        ))

    return results


@router.get("/incidents", response_model=list[IncidentModel])
def get_security_incidents(auth: dict = Depends(verify_operator_auth)):
    """Return deterministic explainable security incidents detected by the rule engine."""
    _, _, _, engine, _, _, _ = _get_engine_and_data()

    incidents: list[IncidentModel] = []
    for inc in engine.incidents:
        if inc.incident_type == "unexpected_role_change":
            rec_action = "Immediately freeze user session, revoke unauthorized role grant, and verify identity credentials."
        elif inc.incident_type == "review_after_role_change":
            rec_action = "Audit accessed resources in session, revoke elevated permissions, and rotate affected keys."
        else:
            rec_action = "Isolate service account token, audit cross-service hops, and verify zero unauthorized allows."

        incidents.append(IncidentModel(
            incident_id=inc.incident_id,
            rule_id=inc.rule_id,
            incident_type=inc.incident_type,
            actor_id=inc.actor_id,
            severity=inc.severity,
            explanation=inc.explanation,
            evidence_event_ids=inc.evidence_event_ids,
            created_at=str(inc.created_at),
            recommended_action=rec_action,
        ))
    return incidents


@router.get("/service-graph", response_model=ServiceGraphResponse)
def get_service_graph(auth: dict = Depends(verify_operator_auth)):
    """Return topological service nodes and directed edges derived dynamically from DetectionEngine."""
    events, _, _, engine, classifications, _, _ = _get_engine_and_data()
    class_map = {c.event_id: c for c in classifications}

    all_services = set()
    for ev in events:
        all_services.add(ev.source_service)
        all_services.add(ev.target_service)

    nodes = [
        ServiceGraphNode(id=s, label=s.upper(), tier="core" if s in ("identity", "portal") else "service")
        for s in sorted(all_services)
    ]

    edges_map: dict[tuple[str, str], ServiceGraphEdge] = {}
    for ev in events:
        src = ev.source_service
        dst = ev.target_service
        key = (src, dst)
        cls = class_map.get(ev.event_id)

        if cls and cls.label == "lateral_movement_candidate":
            status = "suspicious_attempted"
        elif ev.outcome == "deny":
            status = "denied"
        else:
            status = "normal"

        if key not in edges_map:
            edges_map[key] = ServiceGraphEdge(
                source=src,
                target=dst,
                status=status,
                evidence_events=[ev.event_id],
            )
        else:
            edges_map[key].evidence_events.append(ev.event_id)
            if status == "suspicious_attempted":
                edges_map[key].status = "suspicious_attempted"

    return ServiceGraphResponse(nodes=nodes, edges=list(edges_map.values()))


@router.get("/metrics", response_model=DetectionMetricsResponse)
def get_detection_metrics(auth: dict = Depends(verify_operator_auth)):
    """Return live measured detection metrics on official practice dataset (evaluation mode)."""
    _, _, _, _, _, metrics, throughput_eps = _get_engine_and_data()

    flat_cm: dict[str, int] = {}
    for true_lbl, preds in metrics.confusion_matrix.items():
        for pred_lbl, count in preds.items():
            flat_cm[f"{true_lbl}->{pred_lbl}"] = count

    med_us = round(metrics.median_time_to_alert_ms * 1000.0, 2)
    benign_total = metrics.true_negatives + metrics.false_positives
    fp_per_1000 = round((metrics.false_positives / benign_total) * 1000.0, 2) if benign_total > 0 else 0.0

    return DetectionMetricsResponse(
        dataset_name="Official Track 4 Practice Dataset (22 Events)",
        total_events=metrics.total_events,
        exact_accuracy=metrics.exact_accuracy,
        precision=metrics.precision,
        recall=metrics.recall,
        f1_score=metrics.f1_score,
        false_alerts_per_1000_benign=fp_per_1000,
        median_alert_latency_us=med_us,
        throughput_events_per_sec=throughput_eps,
        confusion_matrix=flat_cm,
    )
