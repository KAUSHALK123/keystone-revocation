"""Pure deterministic, explainable rule definitions for threat detection."""
from dataclasses import dataclass
from typing import Any

from quantumvault.detection.models import ClassificationResult, SecurityEvent


@dataclass
class DetectionRule:
    rule_id: str
    rule_name: str
    target_label: str
    severity: str  # info, low, medium, high, critical
    description: str


RULES = {
    "RULE-001": DetectionRule(
        rule_id="RULE-001",
        rule_name="Approved Operational Change",
        target_label="approved_change",
        severity="info",
        description="Operational change or role transition fully matched against authorized change record"
    ),
    "RULE-002": DetectionRule(
        rule_id="RULE-002",
        rule_name="Unexpected Role Elevation",
        target_label="unexpected_role_change",
        severity="high",
        description="Actor underwent role elevation without a corresponding approved change record"
    ),
    "RULE-003": DetectionRule(
        rule_id="RULE-003",
        rule_name="Review Activity Following Unapproved Role Transition",
        target_label="review_after_role_change",
        severity="high",
        description="Sensitive resource access permitted following unapproved role elevation in the same session"
    ),
    "RULE-004": DetectionRule(
        rule_id="RULE-004",
        rule_name="Candidate Lateral Movement Sequence",
        target_label="lateral_movement_candidate",
        severity="critical",
        description="Correlated multi-hop progression across unexpected service boundaries resulting in access denials"
    ),
    "RULE-005": DetectionRule(
        rule_id="RULE-005",
        rule_name="Routine Post-Revocation Access Denial",
        target_label="routine_denial",
        severity="info",
        description="Expected access denial enforcing an approved credential or role revocation"
    ),
    "RULE-006": DetectionRule(
        rule_id="RULE-006",
        rule_name="Isolated Access Denial",
        target_label="isolated_denial",
        severity="low",
        description="Isolated access denial that does not form part of a multi-hop lateral movement progression"
    ),
    "RULE-007": DetectionRule(
        rule_id="RULE-007",
        rule_name="Delayed Network Transit Delivery",
        target_label="routine_delayed_delivery",
        severity="info",
        description="Routine event received out of chronological sequence due to network transit delay"
    ),
    "RULE-008": DetectionRule(
        rule_id="RULE-008",
        rule_name="Corrected Source Clock Offset",
        target_label="routine_clock_offset",
        severity="info",
        description="Routine access with non-zero source clock offset normalized against UTC reference"
    ),
    "RULE-009": DetectionRule(
        rule_id="RULE-009",
        rule_name="Routine Access",
        target_label="routine",
        severity="info",
        description="Normal, authorized activity over known service topology within granted role permissions"
    ),
}
