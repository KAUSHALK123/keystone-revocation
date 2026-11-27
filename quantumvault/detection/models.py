"""Data models for security telemetry, approvals, classifications, and evaluation metrics."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class SecurityEvent:
    event_id: str
    event_time_utc: str
    received_time_utc: str
    source_clock_offset_ms: int
    actor: str
    source_service: str
    target_service: str
    action: str
    role_before: str
    role_after: str
    outcome: str
    approval_id: str | None = None
    session_id: str | None = None
    correlation_id: str | None = None
    corrected_time_utc: str = ""

    def __post_init__(self) -> None:
        if not self.corrected_time_utc:
            self.corrected_time_utc = self.event_time_utc


@dataclass
class ApprovalChange:
    approval_id: str
    approved_by: str
    subject: str
    operation: str  # e.g. "grant_role", "revoke_role"
    role: str
    scope: list[str] = field(default_factory=list)
    valid_from_utc: str | None = None
    valid_until_utc: str | None = None
    effective_at_utc: str | None = None


@dataclass
class ClassificationResult:
    event_id: str
    label: str  # e.g. "routine", "approved_change", "unexpected_role_change", etc.
    reason: str
    rule_id: str
    incident_id: str | None = None
    is_suspicious: bool = False
    evidence_event_ids: list[str] = field(default_factory=list)
    latency_ms: float = 0.0


@dataclass
class Incident:
    incident_id: str
    rule_id: str
    incident_type: str
    actor_id: str
    severity: str  # low, medium, high, critical
    explanation: str
    status: str = "open"
    evidence_event_ids: list[str] = field(default_factory=list)
    involved_services: list[str] = field(default_factory=list)
    created_at: str = ""


@dataclass
class EvaluationMetrics:
    total_events: int
    exact_matches: int
    exact_accuracy: float
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    median_time_to_alert_ms: float
    confusion_matrix: dict[str, dict[str, int]]
