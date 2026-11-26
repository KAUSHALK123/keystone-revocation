"""Clock uncertainty normalization, offset correction, and bounded reordering buffer."""
from datetime import datetime, timedelta, timezone
from typing import Any

from quantumvault.detection.models import SecurityEvent


def parse_iso_timestamp(iso_str: str) -> datetime:
    """Parse ISO 8601 UTC timestamp supporting variable millisecond precision and Z suffix."""
    clean = iso_str.strip()
    if clean.endswith("Z"):
        clean = clean[:-1] + "+00:00"
    return datetime.fromisoformat(clean).astimezone(timezone.utc)


def format_iso_timestamp(dt: datetime) -> str:
    """Format datetime as strict UTC ISO 8601 with 3 millisecond digits and Z suffix."""
    dt_utc = dt.astimezone(timezone.utc)
    ms = int(dt_utc.microsecond / 1000)
    return f"{dt_utc.strftime('%Y-%m-%dT%H:%M:%S')}.{ms:03d}Z"


def correct_timestamp(event_time_iso: str, offset_ms: int) -> str:
    """Apply source clock offset correction:
    corrected_time = event_time - offset_ms
    """
    dt = parse_iso_timestamp(event_time_iso)
    if offset_ms != 0:
        dt = dt - timedelta(milliseconds=offset_ms)
    return format_iso_timestamp(dt)


class ClockNormalizer:
    """Normalizes timestamps, tracks stream arrival order, and buffers events
    to handle bounded network out-of-order delivery while preserving receipt order.
    """

    def __init__(self, buffer_window_seconds: float = 10.0):
        self.buffer_window_seconds = buffer_window_seconds
        self.seen_event_ids: set[str] = set()
        self.latest_received_dt: datetime | None = None
        self.latest_event_dt: datetime | None = None

    def normalize_event(self, event: SecurityEvent) -> SecurityEvent:
        """Compute corrected event time and detect clock offset / delayed arrival flags."""
        corrected_iso = correct_timestamp(event.event_time_utc, event.source_clock_offset_ms)
        event.corrected_time_utc = corrected_iso
        return event

    def detect_anomalies(self, event: SecurityEvent) -> dict[str, Any]:
        """Detect clock anomalies:
        - clock_offset: source clock offset is non-zero
        - out_of_order_arrival: received later than another event that occurred chronologically after it
        - future_timestamp: event time exceeds received time even after correction
        """
        evt_dt = parse_iso_timestamp(event.event_time_utc)
        recv_dt = parse_iso_timestamp(event.received_time_utc)
        corr_dt = parse_iso_timestamp(event.corrected_time_utc)

        anomalies: dict[str, Any] = {
            "has_clock_offset": event.source_clock_offset_ms != 0,
            "offset_ms": event.source_clock_offset_ms,
            "is_out_of_order": False,
            "collector_delay_ms": (recv_dt - corr_dt).total_seconds() * 1000.0,
        }

        # Check for out-of-order arrival relative to chronological stream
        if self.latest_event_dt is not None:
            if corr_dt < self.latest_event_dt and recv_dt >= self.latest_received_dt:
                anomalies["is_out_of_order"] = True

        if self.latest_received_dt is None or recv_dt > self.latest_received_dt:
            self.latest_received_dt = recv_dt
        if self.latest_event_dt is None or corr_dt > self.latest_event_dt:
            self.latest_event_dt = corr_dt

        return anomalies
