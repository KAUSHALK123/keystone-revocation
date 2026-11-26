"""CSV and JSON ingestion parsers for telemetry events, ground-truth labels, and approvals."""
import csv
import json
from pathlib import Path
from typing import Any

from quantumvault.detection.approvals import ApprovalRegistry
from quantumvault.detection.models import ApprovalChange, SecurityEvent


def load_events_from_csv(path: Path | str) -> list[SecurityEvent]:
    """Parse CSV telemetry file into typed SecurityEvent objects."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Telemetry file not found: {path}")

    events: list[SecurityEvent] = []
    with open(p, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append(SecurityEvent(
                event_id=row["event_id"].strip(),
                event_time_utc=row["event_time_utc"].strip(),
                received_time_utc=row["received_time_utc"].strip(),
                source_clock_offset_ms=int(row.get("source_clock_offset_ms", 0) or 0),
                actor=row["actor"].strip(),
                source_service=row["source_service"].strip(),
                target_service=row["target_service"].strip(),
                action=row["action"].strip(),
                role_before=row.get("role_before", "").strip(),
                role_after=row.get("role_after", "").strip(),
                outcome=row["outcome"].strip(),
                approval_id=row.get("approval_id", "").strip() or None,
                session_id=row.get("session_id", "").strip() or None,
                correlation_id=row.get("correlation_id", "").strip() or None
            ))
    return events


def load_labels_from_csv(path: Path | str) -> dict[str, dict[str, str]]:
    """Parse ground-truth labels CSV file into a mapping of event_id -> dict(label, reason)."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Labels file not found: {path}")

    labels: dict[str, dict[str, str]] = {}
    with open(p, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            labels[row["event_id"].strip()] = {
                "label": row["label"].strip(),
                "reason": row["reason"].strip()
            }
    return labels


def load_approvals_from_json(path: Path | str) -> ApprovalRegistry:
    """Parse approvals JSON file into an ApprovalRegistry."""
    registry = ApprovalRegistry()
    registry.load_from_file(path)
    return registry
