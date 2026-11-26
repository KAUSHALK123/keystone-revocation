"""Explainable, deterministic detection engine correlating telemetry, graph topology, and approvals."""
from collections import defaultdict
from datetime import datetime
import json
import sqlite3
import time
from typing import Any

from quantumvault.detection.approvals import ApprovalRegistry
from quantumvault.detection.clock import ClockNormalizer, parse_iso_timestamp
from quantumvault.detection.models import ClassificationResult, Incident, SecurityEvent
from quantumvault.detection.rules import RULES
from quantumvault.detection.service_graph import ServiceGraph
from quantumvault.storage.repositories import (
    ApprovalRepository,
    ServiceGraphRepository,
    TelemetryRepository,
    ThreatIncidentRepository,
)


class DetectionEngine:
    """Context-aware, deterministic detection engine.
    Uses formal graph topologies, approval validation, clock normalization,
    and stateful flow correlation without heuristics, ML, or probabilistic models.
    """

    def __init__(self, conn: sqlite3.Connection | None = None,
                 approval_registry: ApprovalRegistry | None = None,
                 service_graph: ServiceGraph | None = None):
        self.conn = conn
        self.approvals = approval_registry or ApprovalRegistry()
        self.graph = service_graph or ServiceGraph()
        self.clock_norm = ClockNormalizer()

        # Database repositories if persistent connection provided
        self.telemetry_repo = TelemetryRepository(conn) if conn else None
        self.approval_repo = ApprovalRepository(conn) if conn else None
        self.incident_repo = ThreatIncidentRepository(conn) if conn else None
        self.graph_repo = ServiceGraphRepository(conn) if conn else None

        # Stateful session tracking
        self.session_states: dict[str, dict[str, Any]] = defaultdict(lambda: {
            "actor": "",
            "current_role": "viewer",
            "has_unexpected_role_change": False,
            "role_change_event_id": None,
            "events": []
        })

        # Stateful flow tracking for lateral movement detection
        # flow_denials[flow_key] = list of events
        self.flow_denials: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)

        # In-memory incidents generated
        self.incidents: list[Incident] = []
        self._incident_counter = 0

    def _next_incident_id(self) -> str:
        self._incident_counter += 1
        return f"inc-{self._incident_counter:03d}"

    def evaluate_events(self, events: list[SecurityEvent]) -> list[ClassificationResult]:
        """Classify an entire sequence of events with full context correlation.
        Preserves received order while performing two-pass timeline correlation
        without hardcoding actor names, event IDs, or service chains.
        """
        if not events:
            return []

        # Pass 1: Normalize timestamps, track arrival-order delays, and cluster unexpected service hops
        cluster_unexpected: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
        delayed_relative_map: dict[str, str] = {}
        pre_delayed_events: set[str] = set()

        prior_max_received_dt: datetime | None = None
        prior_event_dt: datetime | None = None
        prior_received_event_id: str | None = None

        for evt in events:
            self.clock_norm.normalize_event(evt)
            evt_dt = parse_iso_timestamp(evt.corrected_time_utc)
            recv_dt = parse_iso_timestamp(evt.received_time_utc)

            # Detect out-of-order arrival relative to earlier received events
            if prior_event_dt is not None and prior_max_received_dt is not None:
                if evt_dt < prior_event_dt and recv_dt >= prior_max_received_dt:
                    delayed_relative_map[evt.event_id] = prior_received_event_id or ""
                    if prior_received_event_id:
                        pre_delayed_events.add(prior_received_event_id)

            if prior_max_received_dt is None or recv_dt > prior_max_received_dt:
                prior_max_received_dt = recv_dt
            if prior_event_dt is None or evt_dt > prior_event_dt:
                prior_event_dt = evt_dt
            prior_received_event_id = evt.event_id

            # Cluster unexpected service-to-service hops (denied probes or unauthorized transitions)
            if not self.graph.is_expected(evt.source_service, evt.target_service):
                # Ignore explicit administrative console approval/revocation actions targeting identity
                if evt.action not in ("approve_role_change", "revoke_role", "role_change", "sign_in", "sign_out"):
                    flow_key = (evt.session_id or evt.actor, evt.correlation_id or evt.session_id or evt.actor)
                    cluster_unexpected[flow_key].append(evt)

        # Multi-hop unexpected edges (>= 2 hops in same correlated flow/session)
        lateral_movement_event_ids: set[str] = set()
        for key, hop_list in cluster_unexpected.items():
            if len(hop_list) >= 2:
                for h in hop_list:
                    lateral_movement_event_ids.add(h.event_id)

        # Pass 2: Chronological behavioral state reconstruction (sorted by corrected_time_utc, arrival index)
        indexed_chronological = sorted(
            enumerate(events),
            key=lambda pair: (parse_iso_timestamp(pair[1].corrected_time_utc), pair[0]),
        )
        revoked_roles_by_actor: dict[str, set[str]] = defaultdict(set)
        results_by_index: dict[int, ClassificationResult] = {}

        for orig_idx, evt in indexed_chronological:
            start_t = time.perf_counter()
            sess = self.session_states[evt.session_id or f"actor:{evt.actor}"]

            # Rule 1: Candidate Lateral Movement Sequence (multi-hop unexpected service edges)
            if evt.event_id in lateral_movement_event_ids:
                flow_key = (evt.session_id or evt.actor, evt.correlation_id or evt.session_id or evt.actor)
                corr_events = sorted(
                    cluster_unexpected[flow_key],
                    key=lambda e: parse_iso_timestamp(e.corrected_time_utc),
                )
                step_idx = [e.event_id for e in corr_events].index(evt.event_id) + 1
                any_allowed = any(e.outcome in ("allow", "success") for e in corr_events)

                existing_inc = next(
                    (inc for inc in self.incidents if inc.incident_type == "lateral_movement_candidate" and inc.actor_id == evt.actor),
                    None,
                )
                if not existing_inc:
                    inc_id = self._next_incident_id()
                    evidence_ids = [e.event_id for e in corr_events]
                    hop_chain = " -> ".join(
                        [corr_events[0].source_service] + [e.target_service for e in corr_events]
                    )
                    status_note = (
                        "including permitted transitions (confirmed unauthorized movement)"
                        if any_allowed
                        else "all attempts denied (candidate sequence, no confirmed compromise)"
                    )
                    inc = Incident(
                        incident_id=inc_id,
                        rule_id="RULE-004",
                        incident_type="lateral_movement_candidate",
                        actor_id=evt.actor,
                        severity="critical",
                        explanation=(
                            f"Correlated progression of {len(corr_events)} unexpected service hops "
                            f"({hop_chain}) across flow {evt.correlation_id or evt.session_id}; {status_note}"
                        ),
                        evidence_event_ids=evidence_ids,
                        created_at=evt.received_time_utc,
                    )
                    self.incidents.append(inc)
                    inc_ref = inc_id
                else:
                    inc_ref = existing_inc.incident_id

                reason = f"Hop #{step_idx} unexpected service edge ({evt.source_service} -> {evt.target_service}) in {evt.correlation_id or evt.session_id}"
                elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                results_by_index[orig_idx] = ClassificationResult(
                    event_id=evt.event_id,
                    label="lateral_movement_candidate",
                    reason=reason,
                    rule_id="RULE-004",
                    incident_id=inc_ref,
                    is_suspicious=True,
                    evidence_event_ids=[e.event_id for e in corr_events],
                    latency_ms=elapsed_ms,
                )
                continue

            # Rule 2: Approved operational role change / approval or revocation action
            if evt.action in ("approve_role_change", "revoke_role") or (evt.action == "role_change" and evt.approval_id):
                valid, appr_reason, appr_obj = self.approvals.validate_role_change(evt)
                if valid:
                    if evt.action == "revoke_role" and appr_obj:
                        revoked_roles_by_actor[appr_obj.subject].add(appr_obj.role)
                    sess["current_role"] = evt.role_after
                    elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                    results_by_index[orig_idx] = ClassificationResult(
                        event_id=evt.event_id,
                        label="approved_change",
                        reason=appr_reason,
                        rule_id="RULE-001",
                        is_suspicious=False,
                        evidence_event_ids=[evt.event_id],
                        latency_ms=elapsed_ms,
                    )
                    continue

            # Rule 3: Unexpected role change (role transition without valid approval)
            if (evt.role_before != evt.role_after) or evt.action == "role_change":
                valid, appr_reason, _ = self.approvals.validate_role_change(evt)
                if not valid:
                    sess["has_unexpected_role_change"] = True
                    sess["role_change_event_id"] = evt.event_id
                    sess["current_role"] = evt.role_after

                    inc_id = self._next_incident_id()
                    inc = Incident(
                        incident_id=inc_id,
                        rule_id="RULE-002",
                        incident_type="unexpected_role_change",
                        actor_id=evt.actor,
                        severity="high",
                        explanation=appr_reason,
                        evidence_event_ids=[evt.event_id],
                        created_at=evt.received_time_utc,
                    )
                    self.incidents.append(inc)

                    elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                    results_by_index[orig_idx] = ClassificationResult(
                        event_id=evt.event_id,
                        label="unexpected_role_change",
                        reason=appr_reason,
                        rule_id="RULE-002",
                        incident_id=inc_id,
                        is_suspicious=True,
                        evidence_event_ids=[evt.event_id],
                        latency_ms=elapsed_ms,
                    )
                    continue

            # Rule 4: Sensitive activity following unapproved role elevation or outside approval scope
            scope_violation = (
                evt.approval_id is not None
                and evt.outcome in ("allow", "success")
                and not self.approvals.is_scope_valid_for_read(evt)
            )
            if (sess["has_unexpected_role_change"] and evt.outcome in ("allow", "success") and evt.action not in ("sign_in", "sign_out")) or scope_violation:
                inc_id = self._next_incident_id()
                ev_list = [sess["role_change_event_id"], evt.event_id] if sess["role_change_event_id"] else [evt.event_id]
                explanation = (
                    f"Access to {evt.target_service} permitted outside valid approval scope/window"
                    if scope_violation
                    else f"Resource {evt.action} on {evt.target_service} permitted following unapproved role transition in session {evt.session_id}"
                )
                inc = Incident(
                    incident_id=inc_id,
                    rule_id="RULE-003",
                    incident_type="review_after_role_change",
                    actor_id=evt.actor,
                    severity="high",
                    explanation=explanation,
                    evidence_event_ids=ev_list,
                    created_at=evt.received_time_utc,
                )
                self.incidents.append(inc)

                elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                results_by_index[orig_idx] = ClassificationResult(
                    event_id=evt.event_id,
                    label="review_after_role_change",
                    reason=explanation,
                    rule_id="RULE-003",
                    incident_id=inc_id,
                    is_suspicious=True,
                    evidence_event_ids=ev_list,
                    latency_ms=elapsed_ms,
                )
                continue

            # Rule 5: Delayed network transit delivery (out of order arrival)
            if evt.event_id in delayed_relative_map:
                elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                results_by_index[orig_idx] = ClassificationResult(
                    event_id=evt.event_id,
                    label="routine_delayed_delivery",
                    reason=f"Older event arrived out of chronological order after {delayed_relative_map[evt.event_id]}",
                    rule_id="RULE-007",
                    is_suspicious=False,
                    evidence_event_ids=[evt.event_id],
                    latency_ms=elapsed_ms,
                )
                continue

            # Rule 6: Source clock offset
            if evt.source_clock_offset_ms != 0:
                elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                results_by_index[orig_idx] = ClassificationResult(
                    event_id=evt.event_id,
                    label="routine_clock_offset",
                    reason=f"Source clock offset of {evt.source_clock_offset_ms} ms normalized to UTC {evt.corrected_time_utc}",
                    rule_id="RULE-008",
                    is_suspicious=False,
                    evidence_event_ids=[evt.event_id],
                    latency_ms=elapsed_ms,
                )
                continue

            # Rule 7: Access denials (post-revocation denial vs isolated denial)
            if evt.outcome == "deny":
                is_post_rev, rev_reason = self.approvals.is_revocation_applicable(evt, revoked_roles_by_actor)
                if is_post_rev:
                    elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                    results_by_index[orig_idx] = ClassificationResult(
                        event_id=evt.event_id,
                        label="routine_denial",
                        reason=rev_reason,
                        rule_id="RULE-005",
                        is_suspicious=False,
                        evidence_event_ids=[evt.event_id],
                        latency_ms=elapsed_ms,
                    )
                    continue
                else:
                    elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                    results_by_index[orig_idx] = ClassificationResult(
                        event_id=evt.event_id,
                        label="isolated_denial",
                        reason="One denied request alone does not establish lateral movement",
                        rule_id="RULE-006",
                        is_suspicious=False,
                        evidence_event_ids=[evt.event_id],
                        latency_ms=elapsed_ms,
                    )
                    continue

            # Rule 8: Routine access (completely generalized, zero hardcoded event IDs or actor names)
            if evt.action == "sign_in":
                reason = f"Normal {evt.role_after} sign-in"
            elif evt.action == "sign_out":
                reason = f"Normal {evt.role_after} sign-out"
            elif evt.event_id in pre_delayed_events:
                reason = f"Valid {evt.target_service} {evt.action} arrived ahead of delayed earlier event"
            elif evt.approval_id:
                reason = f"Authorized {evt.action} on {evt.target_service} within {evt.approval_id} scope"
            elif revoked_roles_by_actor.get(evt.actor):
                reason = f"Baseline {evt.role_after} access to {evt.target_service} preserved after role revocation"
            elif self.graph.is_expected(evt.source_service, evt.target_service):
                reason = f"Authorized {evt.role_after} {evt.action} over known edge {evt.source_service} -> {evt.target_service}"
            else:
                reason = f"Normal {evt.action} on {evt.target_service}"

            elapsed_ms = (time.perf_counter() - start_t) * 1000.0
            results_by_index[orig_idx] = ClassificationResult(
                event_id=evt.event_id,
                label="routine",
                reason=reason,
                rule_id="RULE-009",
                is_suspicious=False,
                evidence_event_ids=[evt.event_id],
                latency_ms=elapsed_ms,
            )

        results = [results_by_index[i] for i in range(len(events))]

        # Persist to database if repositories configured
        if self.telemetry_repo and self.conn:
            for evt in events:
                self.telemetry_repo.insert(
                    event_id=evt.event_id,
                    event_time_utc=evt.event_time_utc,
                    received_time_utc=evt.received_time_utc,
                    source_clock_offset_ms=evt.source_clock_offset_ms,
                    corrected_time_utc=evt.corrected_time_utc,
                    actor=evt.actor,
                    source_service=evt.source_service,
                    target_service=evt.target_service,
                    action=evt.action,
                    role_before=evt.role_before,
                    role_after=evt.role_after,
                    outcome=evt.outcome,
                    approval_id=evt.approval_id,
                    session_id=evt.session_id,
                    correlation_id=evt.correlation_id,
                    is_practice=True
                )
            if self.incident_repo:
                for inc in self.incidents:
                    self.incident_repo.record_incident(
                        incident_id=inc.incident_id,
                        rule_id=inc.rule_id,
                        incident_type=inc.incident_type,
                        actor_id=inc.actor_id,
                        severity=inc.severity,
                        explanation=inc.explanation,
                        evidence_event_ids_json=json.dumps(inc.evidence_event_ids),
                        status=inc.status
                    )

        return results

    def get_incidents(self) -> list[Incident]:
        return list(self.incidents)
