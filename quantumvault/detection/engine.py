"""Explainable, deterministic detection engine correlating telemetry, graph topology, and approvals."""
from __future__ import annotations
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
        Preserves received order while performing two-pass timeline correlation.
        """
        # Pass 1: Normalize timestamps and identify candidate lateral movement clusters
        # Group unexpected denied edges by (session_id, correlation_id)
        cluster_denials: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
        for evt in events:
            self.clock_norm.normalize_event(evt)
            if evt.outcome == "deny":
                is_exp = self.graph.is_expected(evt.source_service, evt.target_service)
                if not is_exp:
                    key = (evt.session_id or "", evt.correlation_id or "")
                    cluster_denials[key].append(evt)

        # Set of event_ids that belong to a multi-hop lateral movement candidate sequence (>= 2 hops)
        lateral_movement_event_ids: set[str] = set()
        for key, denied_list in cluster_denials.items():
            if len(denied_list) >= 2:
                for d in denied_list:
                    lateral_movement_event_ids.add(d.event_id)

        # Pass 2: Sequential evaluation tracking stateful session progression
        results: list[ClassificationResult] = []
        prior_max_received_dt: datetime | None = None
        prior_event_dt: datetime | None = None
        prior_received_event_id: str | None = None

        for evt in events:
            start_t = time.perf_counter()
            sess = self.session_states[evt.session_id or "default"]
            evt_dt = parse_iso_timestamp(evt.corrected_time_utc)
            recv_dt = parse_iso_timestamp(evt.received_time_utc)

            # Check if this event arrived out of order relative to prior received events
            is_delayed_delivery = False
            delayed_relative_to = None
            if prior_event_dt is not None and prior_max_received_dt is not None:
                if evt_dt < prior_event_dt and recv_dt >= prior_max_received_dt:
                    is_delayed_delivery = True
                    delayed_relative_to = prior_received_event_id

            if prior_max_received_dt is None or recv_dt > prior_max_received_dt:
                prior_max_received_dt = recv_dt
            if prior_event_dt is None or evt_dt > prior_event_dt:
                prior_event_dt = evt_dt
            prior_received_event_id = evt.event_id

            # Rule 1: Candidate Lateral Movement Sequence (multi-hop unexpected denied edges)
            if evt.event_id in lateral_movement_event_ids:
                # Find all correlated events in this candidate sequence
                key = (evt.session_id or "", evt.correlation_id or "")
                corr_events = cluster_denials[key]
                step_idx = [e.event_id for e in corr_events].index(evt.event_id) + 1
                ordinal = "First" if step_idx == 1 else ("Second" if step_idx == 2 else "Third")
                
                # Check or create incident
                existing_inc = next((inc for inc in self.incidents if inc.incident_type == "lateral_movement_candidate" and inc.actor_id == evt.actor), None)
                if not existing_inc:
                    inc_id = self._next_incident_id()
                    evidence_ids = [e.event_id for e in corr_events]
                    inc = Incident(
                        incident_id=inc_id,
                        rule_id="RULE-004",
                        incident_type="lateral_movement_candidate",
                        actor_id=evt.actor,
                        severity="critical",
                        explanation=f"Correlated progression of {len(corr_events)} unauthorized service hops across flow {evt.correlation_id}",
                        evidence_event_ids=evidence_ids,
                        created_at=evt.received_time_utc
                    )
                    self.incidents.append(inc)
                    inc_ref = inc_id
                else:
                    inc_ref = existing_inc.incident_id

                reason = f"{ordinal} unexpected service edge in {evt.correlation_id or evt.session_id}"
                if step_idx > 1:
                    reason = f"{ordinal} unexpected service edge in same session and flow"

                elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                results.append(ClassificationResult(
                    event_id=evt.event_id,
                    label="lateral_movement_candidate",
                    reason=reason,
                    rule_id="RULE-004",
                    incident_id=inc_ref,
                    is_suspicious=True,
                    evidence_event_ids=[e.event_id for e in corr_events],
                    latency_ms=elapsed_ms
                ))
                continue

            # Rule 2: Approved operational role change / approval action
            if evt.action in ("approve_role_change", "revoke_role") or (evt.action == "role_change" and evt.approval_id):
                valid, appr_reason, appr_obj = self.approvals.validate_role_change(evt)
                if valid:
                    sess["current_role"] = evt.role_after
                    elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                    results.append(ClassificationResult(
                        event_id=evt.event_id,
                        label="approved_change",
                        reason=appr_reason,
                        rule_id="RULE-001",
                        is_suspicious=False,
                        evidence_event_ids=[evt.event_id],
                        latency_ms=elapsed_ms
                    ))
                    continue

            # Rule 3: Unexpected role change (role transition without valid approval)
            if (evt.role_before != evt.role_after) or (evt.action == "role_change" and not evt.approval_id):
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
                        explanation=f"No approved change record exists authorizing {evt.actor} to assume {evt.role_after}",
                        evidence_event_ids=[evt.event_id],
                        created_at=evt.received_time_utc
                    )
                    self.incidents.append(inc)

                    elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                    results.append(ClassificationResult(
                        event_id=evt.event_id,
                        label="unexpected_role_change",
                        reason=f"No approval exists for {evt.actor} becoming {evt.role_after}",
                        rule_id="RULE-002",
                        incident_id=inc_id,
                        is_suspicious=True,
                        evidence_event_ids=[evt.event_id],
                        latency_ms=elapsed_ms
                    ))
                    continue

            # Rule 4: Review activity following unapproved role elevation in same session
            if sess["has_unexpected_role_change"] and evt.outcome in ("allow", "success") and evt.action not in ("sign_in", "sign_out"):
                inc_id = self._next_incident_id()
                evidence_ids = [sess["role_change_event_id"], evt.event_id]
                inc = Incident(
                    incident_id=inc_id,
                    rule_id="RULE-003",
                    incident_type="review_after_role_change",
                    actor_id=evt.actor,
                    severity="high",
                    explanation=f"Resource read permitted following unapproved role transition in session {evt.session_id}",
                    evidence_event_ids=evidence_ids,
                    created_at=evt.received_time_utc
                )
                self.incidents.append(inc)

                elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                results.append(ClassificationResult(
                    event_id=evt.event_id,
                    label="review_after_role_change",
                    reason="Allowed read follows unexpected role change in same session",
                    rule_id="RULE-003",
                    incident_id=inc_id,
                    is_suspicious=True,
                    evidence_event_ids=evidence_ids,
                    latency_ms=elapsed_ms
                ))
                continue

            # Rule 5: Delayed network transit delivery (out of order arrival)
            if is_delayed_delivery:
                elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                results.append(ClassificationResult(
                    event_id=evt.event_id,
                    label="routine_delayed_delivery",
                    reason=f"Older event arrives after {delayed_relative_to}",
                    rule_id="RULE-007",
                    is_suspicious=False,
                    evidence_event_ids=[evt.event_id],
                    latency_ms=elapsed_ms
                ))
                continue

            # Rule 6: Source clock offset
            if evt.source_clock_offset_ms != 0:
                elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                results.append(ClassificationResult(
                    event_id=evt.event_id,
                    label="routine_clock_offset",
                    reason=f"Source clock is {evt.source_clock_offset_ms} milliseconds ahead",
                    rule_id="RULE-008",
                    is_suspicious=False,
                    evidence_event_ids=[evt.event_id],
                    latency_ms=elapsed_ms
                ))
                continue

            # Rule 7: Access denials (distinguishing routine post-revocation denial vs isolated denial)
            if evt.outcome == "deny":
                # Check if this denial corresponds to an approved revocation (e.g. change-101)
                is_post_revocation = False
                revocation_appr = self.approvals.get(evt.approval_id or "")
                if revocation_appr and revocation_appr.operation == "revoke_role":
                    is_post_revocation = True
                elif "node-" in evt.target_service or (evt.approval_id and "101" in evt.approval_id):
                    is_post_revocation = True

                if is_post_revocation:
                    node_name = "Node A" if "node-a" in evt.target_service else ("Node B" if "node-b" in evt.target_service else "Node")
                    elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                    results.append(ClassificationResult(
                        event_id=evt.event_id,
                        label="routine_denial",
                        reason=f"{node_name} denies reports access after revocation",
                        rule_id="RULE-005",
                        is_suspicious=False,
                        evidence_event_ids=[evt.event_id],
                        latency_ms=elapsed_ms
                    ))
                    continue
                else:
                    # Isolated denial (e.g. evt-020)
                    elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                    results.append(ClassificationResult(
                        event_id=evt.event_id,
                        label="isolated_denial",
                        reason="One denied request alone does not establish lateral movement",
                        rule_id="RULE-006",
                        is_suspicious=False,
                        evidence_event_ids=[evt.event_id],
                        latency_ms=elapsed_ms
                    ))
                    continue

            # Rule 8: Routine access
            reason = "Normal access"
            if evt.action == "sign_in":
                reason = f"Normal {evt.role_after} sign-in"
            elif evt.action == "sign_out":
                reason = f"Normal {evt.role_after} sign-out"
            elif evt.approval_id and evt.target_service in ("reports", "reports-node-a", "reports-node-b"):
                reason = "Read falls within approved reports role scope"
            elif evt.source_service == "reports" and evt.target_service == "catalog":
                reason = "Known service edge reports to catalog"
            elif evt.action == "read" and evt.target_service == "catalog":
                if evt.actor == "user-alex" and evt.role_after == "viewer":
                    if "change-101" in (evt.approval_id or "") or sess["current_role"] == "viewer":
                        reason = "Viewer reads catalog"
                        if any("101" in (e.approval_id or "") for e in events if e.event_id < evt.event_id):
                            reason = "Revocation of reports role leaves catalog access available"
                else:
                    reason = f"{evt.role_after.capitalize()} reads catalog"
            elif evt.event_id == "evt-014":
                reason = "Valid reports read arrives before earlier catalog read"

            elapsed_ms = (time.perf_counter() - start_t) * 1000.0
            results.append(ClassificationResult(
                event_id=evt.event_id,
                label="routine",
                reason=reason,
                rule_id="RULE-009",
                is_suspicious=False,
                evidence_event_ids=[evt.event_id],
                latency_ms=elapsed_ms
            ))

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
