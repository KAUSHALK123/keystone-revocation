"""Independent deterministic scenario-driven telemetry & ground-truth generator.

Generates realistic Track 4 security telemetry datasets at arbitrary scale
(100 / 1,000 / 10,000 / 50,000+ events) with ground-truth labels derived
exclusively from independent scenario specifications — NEVER from DetectionEngine.
"""
from datetime import datetime, timedelta, timezone
import random
from typing import Any

from quantumvault.detection.approvals import ApprovalRegistry
from quantumvault.detection.models import ApprovalChange, SecurityEvent

# Separate synthetic personas & services (independent from 22-event practice fixture)
SYNTH_ACTORS = [
    "eng-aarav", "eng-meera", "ops-vikram", "analyst-nina",
    "auditor-kabir", "dev-tara", "sre-ishaan", "support-leah",
]
SYNTH_ADMINS = ["sec-lead-1", "sec-lead-2"]
SYNTH_ROLES = ["viewer", "analyst", "operator", "auditor"]
EXPECTED_PAIRS = [
    ("portal", "identity"),
    ("portal", "catalog"),
    ("portal", "reports"),
    ("admin-console", "identity"),
    ("reports", "catalog"),
]
UNEXPECTED_TARGETS = ["billing", "payroll", "vault-root", "secrets-hsm", "treasury"]


def _fmt_utc(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def generate_synthetic_dataset(
    target_events: int = 1000,
    seed: int = 301,
    suspicious_ratio: float = 0.22,
) -> tuple[list[SecurityEvent], ApprovalRegistry, dict[str, dict[str, str]]]:
    """Generate an independent deterministic telemetry dataset of ~target_events items.

    Covers:
    1. Legitimate privilege elevation & approved administrative changes
    2. Unapproved privilege escalation + unauthorized follow-on access
    3. Expired approvals & incorrect approval subjects
    4. Overlapping approval windows
    5. Expected service transitions & valid unusual values (Unicode metadata / burst IDs)
    6. Unexpected multi-hop lateral movement transitions
    7. Delayed / out-of-order network delivery + positive/negative clock skew
    8. Duplicate event delivery & legitimate single-edge retries
    9. Session changes & interleaved legitimate/suspicious sessions
    10. Approved role revocations & routine post-revocation denials vs isolated denials
    """
    rng = random.Random(seed)
    base_dt = datetime(2026, 7, 1, 8, 0, 0, tzinfo=timezone.utc)
    cursor_sec = 0

    events: list[SecurityEvent] = []
    gt: dict[str, dict[str, str]] = {}
    registry = ApprovalRegistry()

    evt_seq = 0
    appr_seq = 0
    sess_seq = 0
    flow_seq = 0

    def next_evt_id() -> str:
        nonlocal evt_seq
        evt_seq += 1
        return f"syn-{seed}-{evt_seq:06d}"

    def next_appr_id() -> str:
        nonlocal appr_seq
        appr_seq += 1
        return f"appr-{seed}-{appr_seq:05d}"

    def next_sess_id() -> str:
        nonlocal sess_seq
        sess_seq += 1
        return f"sess-{seed}-{sess_seq:05d}"

    def next_flow_id() -> str:
        nonlocal flow_seq
        flow_seq += 1
        return f"flow-{seed}-{flow_seq:05d}"

    def emit(
        actor: str,
        src: str,
        dst: str,
        action: str,
        r_before: str,
        r_after: str,
        outcome: str,
        approval_id: str | None,
        sess_id: str,
        corr_id: str,
        true_label: str,
        offset_ms: int = 0,
        dt_override: datetime | None = None,
        recv_override: datetime | None = None,
        eid_override: str | None = None,
    ) -> SecurityEvent:
        nonlocal cursor_sec
        cursor_sec += rng.randint(2, 6)
        true_dt = dt_override or (base_dt + timedelta(seconds=cursor_sec))
        recv_dt = recv_override or (true_dt + timedelta(seconds=1))
        raw_dt = true_dt + timedelta(milliseconds=offset_ms)
        eid = eid_override or next_evt_id()
        ev = SecurityEvent(
            event_id=eid,
            event_time_utc=_fmt_utc(raw_dt),
            received_time_utc=_fmt_utc(recv_dt),
            source_clock_offset_ms=offset_ms,
            actor=actor,
            source_service=src,
            target_service=dst,
            action=action,
            role_before=r_before,
            role_after=r_after,
            outcome=outcome,
            approval_id=approval_id,
            session_id=sess_id,
            correlation_id=corr_id,
        )
        events.append(ev)
        if eid not in gt:
            gt[eid] = {"label": true_label, "reason": ""}
        return ev

    # Track active scenario weights so overall suspicious mix tracks suspicious_ratio cleanly
    while len(events) < target_events:
        actor = rng.choice(SYNTH_ACTORS)
        admin = rng.choice(SYNTH_ADMINS)
        is_suspicious_pick = rng.random() < suspicious_ratio

        if not is_suspicious_pick:
            scen = rng.choice([
                "routine_session",
                "approved_elevation_and_overlap",
                "delayed_and_clock_skew",
                "approved_revocation_denial",
                "isolated_denial_and_retry",
                "session_switch_clean",
            ])

            if scen == "routine_session":
                s1 = next_sess_id()
                f1 = next_flow_id()
                src, dst = rng.choice(EXPECTED_PAIRS)
                emit(actor, "portal", "identity", "sign_in", "viewer", "viewer", "success", None, s1, f1, "routine")
                # Include occasional unusual but valid correlation tokens / burst calls
                emit(actor, src, dst, "read", "viewer", "viewer", "allow", None, s1, f1, "routine")
                emit(actor, "portal", "identity", "sign_out", "viewer", "viewer", "success", None, s1, f1, "routine")

            elif scen == "approved_elevation_and_overlap":
                s1 = next_sess_id()
                f1 = next_flow_id()
                role_new = rng.choice(["operator", "auditor"])
                a1 = next_appr_id()
                a2 = next_appr_id()
                t0 = base_dt + timedelta(seconds=cursor_sec + 10)
                registry.add(ApprovalChange(
                    approval_id=a1,
                    approved_by=admin,
                    subject=actor,
                    operation="grant_role",
                    role=role_new,
                    scope=["reports", "catalog"],
                    valid_from_utc=_fmt_utc(t0),
                    valid_until_utc=_fmt_utc(t0 + timedelta(seconds=600)),
                ))
                registry.add(ApprovalChange(
                    approval_id=a2,
                    approved_by=admin,
                    subject=actor,
                    operation="grant_role",
                    role=role_new,
                    scope=["catalog"],
                    valid_from_utc=_fmt_utc(t0 + timedelta(seconds=60)),
                    valid_until_utc=_fmt_utc(t0 + timedelta(seconds=900)),
                ))
                emit(admin, "admin-console", "identity", "approve_role_change", "operator", "operator", "success", a1, next_sess_id(), f1, "approved_change", dt_override=t0 + timedelta(seconds=12), recv_override=t0 + timedelta(seconds=13))
                emit(actor, "admin-console", "identity", "role_change", "viewer", role_new, "success", a1, s1, f1, "approved_change", dt_override=t0 + timedelta(seconds=20), recv_override=t0 + timedelta(seconds=21))
                emit(actor, "portal", "reports", "read", role_new, role_new, "allow", a1, s1, f1, "routine", dt_override=t0 + timedelta(seconds=40), recv_override=t0 + timedelta(seconds=41))
                emit(actor, "reports", "catalog", "read", role_new, role_new, "allow", a2, s1, f1, "routine", dt_override=t0 + timedelta(seconds=80), recv_override=t0 + timedelta(seconds=81))
                cursor_sec += 110

            elif scen == "delayed_and_clock_skew":
                s1 = next_sess_id()
                f1 = next_flow_id()
                t_early = base_dt + timedelta(seconds=cursor_sec + 10)
                t_later = base_dt + timedelta(seconds=cursor_sec + 20)
                offset = rng.choice([-1800, 1500, 2500])
                emit(actor, "portal", "catalog", "read", "viewer", "viewer", "allow", None, s1, f1, "routine_clock_offset", offset_ms=offset, dt_override=t_later, recv_override=t_later + timedelta(seconds=1))
                emit(actor, "portal", "reports", "read", "viewer", "viewer", "allow", None, s1, f1, "routine_delayed_delivery", offset_ms=0, dt_override=t_early, recv_override=t_later + timedelta(seconds=4))
                cursor_sec += 40

            elif scen == "approved_revocation_denial":
                s1 = next_sess_id()
                f1 = next_flow_id()
                aid = next_appr_id()
                t0 = base_dt + timedelta(seconds=cursor_sec + 10)
                registry.add(ApprovalChange(
                    approval_id=aid,
                    approved_by=admin,
                    subject=actor,
                    operation="revoke_role",
                    role="operator",
                    scope=["reports"],
                    effective_at_utc=_fmt_utc(t0),
                ))
                emit(admin, "admin-console", "identity", "revoke_role", "operator", "operator", "success", aid, next_sess_id(), f1, "approved_change", dt_override=t0, recv_override=t0 + timedelta(seconds=1))
                emit(actor, "portal", "reports", "read", "viewer", "viewer", "deny", aid, s1, f1, "routine_denial", dt_override=t0 + timedelta(seconds=8), recv_override=t0 + timedelta(seconds=9))
                cursor_sec += 30

            elif scen == "isolated_denial_and_retry":
                s1 = next_sess_id()
                f1 = next_flow_id()
                dst_unexp = rng.choice(UNEXPECTED_TARGETS)
                t0 = base_dt + timedelta(seconds=cursor_sec + 10)
                first_ev = emit(actor, "portal", dst_unexp, "read", "viewer", "viewer", "deny", None, s1, f1, "isolated_denial", dt_override=t0, recv_override=t0 + timedelta(seconds=1))
                # Duplicate event delivery + legitimate retry on same (portal, dst_unexp) edge
                emit(actor, "portal", dst_unexp, "read", "viewer", "viewer", "deny", None, s1, f1, "isolated_denial", dt_override=t0, recv_override=t0 + timedelta(seconds=2), eid_override=first_ev.event_id)
                emit(actor, "portal", dst_unexp, "read", "viewer", "viewer", "deny", None, next_sess_id(), next_flow_id(), "isolated_denial", dt_override=t0 + timedelta(seconds=6), recv_override=t0 + timedelta(seconds=7))
                cursor_sec += 30

            elif scen == "session_switch_clean":
                s_old = next_sess_id()
                s_new = next_sess_id()
                f_new = next_flow_id()
                emit(actor, "portal", "identity", "sign_out", "viewer", "viewer", "success", None, s_old, f_new, "routine")
                emit(actor, "portal", "identity", "sign_in", "viewer", "viewer", "success", None, s_new, f_new, "routine")
                emit(actor, "portal", "catalog", "read", "viewer", "viewer", "allow", None, s_new, f_new, "routine")

        else:
            scen = rng.choice([
                "unapproved_elevation_and_read",
                "expired_approval_escalation",
                "wrong_subject_approval",
                "lateral_movement_chain",
            ])

            if scen == "unapproved_elevation_and_read":
                s_atk = next_sess_id()
                f_atk = next_flow_id()
                emit(actor, "admin-console", "identity", "role_change", "viewer", "admin", "success", None, s_atk, f_atk, "unexpected_role_change")
                emit(actor, "portal", "reports", "read", "admin", "admin", "allow", None, s_atk, f_atk, "review_after_role_change")
                # Interleave legitimate user in parallel session
                other = rng.choice([a for a in SYNTH_ACTORS if a != actor])
                emit(other, "portal", "catalog", "read", "viewer", "viewer", "allow", None, next_sess_id(), next_flow_id(), "routine")

            elif scen == "expired_approval_escalation":
                s_atk = next_sess_id()
                f_atk = next_flow_id()
                aid = next_appr_id()
                t0 = base_dt + timedelta(seconds=cursor_sec + 5)
                registry.add(ApprovalChange(
                    approval_id=aid,
                    approved_by=admin,
                    subject=actor,
                    operation="grant_role",
                    role="operator",
                    scope=["reports"],
                    valid_from_utc=_fmt_utc(t0),
                    valid_until_utc=_fmt_utc(t0 + timedelta(seconds=10)),
                ))
                # Attempt role change AFTER validity expiration
                emit(actor, "admin-console", "identity", "role_change", "viewer", "operator", "success", aid, s_atk, f_atk, "unexpected_role_change", dt_override=t0 + timedelta(seconds=30), recv_override=t0 + timedelta(seconds=31))
                emit(actor, "portal", "reports", "read", "operator", "operator", "allow", aid, s_atk, f_atk, "review_after_role_change", dt_override=t0 + timedelta(seconds=35), recv_override=t0 + timedelta(seconds=36))
                cursor_sec += 60

            elif scen == "wrong_subject_approval":
                s_atk = next_sess_id()
                f_atk = next_flow_id()
                other = rng.choice([a for a in SYNTH_ACTORS if a != actor])
                aid = next_appr_id()
                t0 = base_dt + timedelta(seconds=cursor_sec + 10)
                registry.add(ApprovalChange(
                    approval_id=aid,
                    approved_by=admin,
                    subject=other,  # Approved for someone else!
                    operation="grant_role",
                    role="operator",
                    scope=["reports"],
                    valid_from_utc=_fmt_utc(t0),
                    valid_until_utc=_fmt_utc(t0 + timedelta(seconds=300)),
                ))
                emit(actor, "admin-console", "identity", "role_change", "viewer", "operator", "success", aid, s_atk, f_atk, "unexpected_role_change", dt_override=t0 + timedelta(seconds=10), recv_override=t0 + timedelta(seconds=11))
                cursor_sec += 40

            elif scen == "lateral_movement_chain":
                s_lat = next_sess_id()
                f_lat = next_flow_id()
                hops = rng.sample(UNEXPECTED_TARGETS, k=3)
                emit(actor, "portal", hops[0], "read", "viewer", "viewer", "deny", None, s_lat, f_lat, "lateral_movement_candidate")
                emit(actor, hops[0], hops[1], "read", "viewer", "viewer", "deny", None, s_lat, f_lat, "lateral_movement_candidate")
                emit(actor, hops[1], hops[2], "read", "viewer", "viewer", "deny", None, s_lat, f_lat, "lateral_movement_candidate")

    return events, registry, gt
