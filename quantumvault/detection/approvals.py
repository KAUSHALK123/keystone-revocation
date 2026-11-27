"""Approval parsing, validation, and authorization matching against change registry."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any

from quantumvault.detection.clock import parse_iso_timestamp
from quantumvault.detection.models import ApprovalChange, SecurityEvent


class ApprovalRegistry:
    """In-memory and persistent registry of approved operational changes."""

    def __init__(self) -> None:
        self._approvals: dict[str, ApprovalChange] = {}

    def add(self, approval: ApprovalChange) -> None:
        self._approvals[approval.approval_id] = approval

    def get(self, approval_id: str) -> ApprovalChange | None:
        return self._approvals.get(approval_id)

    def load_from_file(self, path: Path | str) -> None:
        p = Path(path)
        if not p.exists():
            return
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.load_from_dict(data)

    def load_from_dict(self, data: dict[str, Any]) -> None:
        changes = data.get("changes", [])
        for item in changes:
            self.add(ApprovalChange(
                approval_id=item["approval_id"],
                approved_by=item.get("approved_by", ""),
                subject=item.get("subject", ""),
                operation=item.get("operation", ""),
                role=item.get("role", ""),
                scope=item.get("scope", []),
                valid_from_utc=item.get("valid_from_utc"),
                valid_until_utc=item.get("valid_until_utc"),
                effective_at_utc=item.get("effective_at_utc")
            ))

    def validate_role_change(self, event: SecurityEvent) -> tuple[bool, str, ApprovalChange | None]:
        """Validate whether a role change or role approval action is backed by a valid approval."""
        # 1. Approval action by an operator (e.g. evt-003)
        if event.action == "approve_role_change":
            if not event.approval_id:
                return False, "Approval action missing approval_id", None
            appr = self.get(event.approval_id)
            if not appr:
                return False, f"Approval ID '{event.approval_id}' not found in registry", None
            if appr.approved_by != event.actor:
                return False, f"Approving actor '{event.actor}' does not match registered approver '{appr.approved_by}'", appr
            return True, f"Operator approves {appr.approval_id}", appr

        # 2. Revocation action by an operator (e.g. evt-016)
        if event.action == "revoke_role":
            if not event.approval_id:
                return False, "Revocation action missing approval_id", None
            appr = self.get(event.approval_id)
            if not appr:
                return False, f"Approval ID '{event.approval_id}' not found in registry", None
            return True, f"Operator revokes {appr.subject} {appr.role} under {appr.approval_id}", appr

        # 3. Role change executed on an actor (e.g. evt-004)
        if event.role_before != event.role_after or event.action == "role_change":
            if not event.approval_id:
                return False, f"No approval exists for {event.actor} becoming {event.role_after}", None

            appr = self.get(event.approval_id)
            if not appr:
                return False, f"Approval ID '{event.approval_id}' not found in registry", None

            if appr.subject != event.actor:
                return False, f"Subject mismatch: approval for '{appr.subject}', event for '{event.actor}'", appr

            if appr.role != event.role_after:
                return False, f"Role mismatch: approval grants '{appr.role}', event changed to '{event.role_after}'", appr

            # Verify time bounds (valid_from_utc inclusive, valid_until_utc exclusive per spec)
            evt_dt = parse_iso_timestamp(event.corrected_time_utc)
            if appr.valid_from_utc:
                from_dt = parse_iso_timestamp(appr.valid_from_utc)
                if evt_dt < from_dt:
                    return False, f"Event time {event.corrected_time_utc} is before approval validity window start {appr.valid_from_utc}", appr
            if appr.valid_until_utc:
                until_dt = parse_iso_timestamp(appr.valid_until_utc)
                if evt_dt >= until_dt:
                    return False, f"Event time {event.corrected_time_utc} is at or after approval validity window end {appr.valid_until_utc}", appr

            return True, f"Approved subject role and time match {appr.approval_id}", appr

        return True, "No role transition occurred", None

    def is_scope_valid_for_read(self, event: SecurityEvent) -> bool:
        """Check if an access request is within the approved scope and active validity window."""
        if not event.approval_id:
            return True  # Routine permissions apply
        appr = self.get(event.approval_id)
        if not appr:
            return False
        if appr.subject != event.actor:
            return False
        if appr.scope and event.target_service not in appr.scope:
            return False
        evt_dt = parse_iso_timestamp(event.corrected_time_utc)
        if appr.valid_from_utc and evt_dt < parse_iso_timestamp(appr.valid_from_utc):
            return False
        if appr.valid_until_utc and evt_dt >= parse_iso_timestamp(appr.valid_until_utc):
            return False
        return True

    def is_revocation_applicable(self, event: SecurityEvent, revoked_roles: dict[str, set[str]]) -> tuple[bool, str]:
        """Check whether an access denial enforces an approved revocation."""
        if event.approval_id:
            appr = self.get(event.approval_id)
            if appr and appr.operation == "revoke_role":
                return True, f"Service {event.target_service} denies access after revocation ({appr.approval_id})"
        actor_revoked = revoked_roles.get(event.actor, set())
        if actor_revoked:
            # Check if any revocation approval scopes this target service
            for appr in self._approvals.values():
                if appr.subject == event.actor and appr.role in actor_revoked:
                    if not appr.scope or event.target_service in appr.scope:
                        return True, f"Service {event.target_service} denies access after revocation of role '{appr.role}'"
        return False, ""
