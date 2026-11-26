"""Synthetic Enterprise Environment for Independent Security Validation.

Provides realistic multi-user, multi-device, multi-service topologies and
isolated runtime environments inside final_security_validation/runtime/.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import time
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from quantumvault.config import get_db_path, get_vault_key_path
from quantumvault.core.service import QuantumVaultService
from quantumvault.crypto.pqc_dsa import MLDSA65
from quantumvault.detection.models import SecurityEvent
from quantumvault.distributed.authority import SecurityAuthority
from quantumvault.distributed.cluster import ClusterCoordinator
from quantumvault.distributed.node import ServiceNode
from quantumvault.iam.authentication import generate_device_keypair, generate_pqc_device_keypair, sign_challenge
from quantumvault.iam.device import DeviceManager
from quantumvault.iam.recovery import RecoveryManager
from quantumvault.storage.db import get_connection, init_db, transaction
from quantumvault.storage.repositories import IdentityRepository


VALIDATION_ROOT = Path(__file__).resolve().parent
RUNTIME_ROOT = VALIDATION_ROOT / "runtime"
EVIDENCE_ROOT = VALIDATION_ROOT / "evidence"
REPORTS_ROOT = VALIDATION_ROOT / "reports"

RUNTIME_ROOT.mkdir(parents=True, exist_ok=True)
EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
REPORTS_ROOT.mkdir(parents=True, exist_ok=True)


@dataclass
class SyntheticDevice:
    device_id: str
    owner: str
    key_type: str  # "mldsa65" or "ed25519"
    public_key_b64: str
    private_key: Any
    status: str = "active"


@dataclass
class SyntheticOrganization:
    users: list[dict[str, str]]
    devices: dict[str, SyntheticDevice]
    assets: dict[str, str]  # asset_id -> owner
    asset_contents: dict[str, str]  # asset_id -> plaintext
    services: list[str]


def generate_synthetic_devices(users: list[str]) -> dict[str, SyntheticDevice]:
    """Generate cryptographically valid keypairs for 10+ synthetic devices."""
    devices: dict[str, SyntheticDevice] = {}
    mldsa = MLDSA65()

    # 1. Alice's Phone A (Ed25519)
    priv_a, pub_a = generate_device_keypair()
    devices["phone-a"] = SyntheticDevice(
        device_id="phone-a",
        owner="alice",
        key_type="ed25519",
        public_key_b64=pub_a,
        private_key=priv_a
    )

    # 2. Alice's Phone B (ML-DSA-65 - Stolen/Revoked)
    sk_b, pk_b_b64 = generate_pqc_device_keypair()
    devices["phone-b"] = SyntheticDevice(
        device_id="phone-b",
        owner="alice",
        key_type="mldsa65",
        public_key_b64=pk_b_b64,
        private_key=sk_b
    )

    # 3. Alice's Phone C (ML-DSA-65 - Replacement Phone)
    sk_c, pk_c_b64 = generate_pqc_device_keypair()
    devices["phone-c"] = SyntheticDevice(
        device_id="phone-c",
        owner="alice",
        key_type="mldsa65",
        public_key_b64=pk_c_b64,
        private_key=sk_c,
        status="unregistered"
    )

    # 4. Alice's Laptop A (Ed25519)
    priv_lap_a, pub_lap_a = generate_device_keypair()
    devices["laptop-a"] = SyntheticDevice(
        device_id="laptop-a",
        owner="alice",
        key_type="ed25519",
        public_key_b64=pub_lap_a,
        private_key=priv_lap_a
    )

    # 5. Bob's Phone (Ed25519)
    priv_bob_p, pub_bob_p = generate_device_keypair()
    devices["phone-bob"] = SyntheticDevice(
        device_id="phone-bob",
        owner="bob",
        key_type="ed25519",
        public_key_b64=pub_bob_p,
        private_key=priv_bob_p
    )

    # 6. Bob's Laptop (ML-DSA-65)
    sk_bob_l, pk_bob_l_b64 = generate_pqc_device_keypair()
    devices["laptop-bob"] = SyntheticDevice(
        device_id="laptop-bob",
        owner="bob",
        key_type="mldsa65",
        public_key_b64=pk_bob_l_b64,
        private_key=sk_bob_l
    )

    # 7. Carol's Tablet (ML-DSA-65)
    sk_carol_t, pk_carol_t_b64 = generate_pqc_device_keypair()
    devices["tablet-carol"] = SyntheticDevice(
        device_id="tablet-carol",
        owner="carol",
        key_type="mldsa65",
        public_key_b64=pk_carol_t_b64,
        private_key=sk_carol_t
    )

    # 8. Dave's Workstation (Ed25519)
    priv_dave, pub_dave = generate_device_keypair()
    devices["workstation-dave"] = SyntheticDevice(
        device_id="workstation-dave",
        owner="dave",
        key_type="ed25519",
        public_key_b64=pub_dave,
        private_key=priv_dave
    )

    # 9. Frank's Executive Terminal (ML-DSA-65)
    sk_frank, pk_frank_b64 = generate_pqc_device_keypair()
    devices["terminal-frank"] = SyntheticDevice(
        device_id="terminal-frank",
        owner="frank",
        key_type="mldsa65",
        public_key_b64=pk_frank_b64,
        private_key=sk_frank
    )

    # 10. Compromised Device (possesses leaked key)
    priv_comp, pub_comp = generate_device_keypair()
    devices["dev-compromised"] = SyntheticDevice(
        device_id="dev-compromised",
        owner="dave",
        key_type="ed25519",
        public_key_b64=pub_comp,
        private_key=priv_comp,
        status="compromised"
    )

    # 11. Unknown Device (never enrolled)
    priv_unk, pub_unk = generate_device_keypair()
    devices["dev-unknown"] = SyntheticDevice(
        device_id="dev-unknown",
        owner="attacker",
        key_type="ed25519",
        public_key_b64=pub_unk,
        private_key=priv_unk,
        status="unenrolled"
    )

    return devices


def create_synthetic_organization() -> SyntheticOrganization:
    """Build a complete synthetic organization with 6 users and 120 assets."""
    users = [
        {"id": "alice", "name": "Alice Researcher", "role": "lead_researcher", "status": "active"},
        {"id": "bob", "name": "Bob Finance", "role": "financial_analyst", "status": "active"},
        {"id": "carol", "name": "Carol SecOps", "role": "secops_admin", "status": "active"},
        {"id": "dave", "name": "Dave Contractor", "role": "contractor", "status": "active"},
        {"id": "eve", "name": "Eve Former", "role": "viewer", "status": "disabled"},
        {"id": "frank", "name": "Frank Executive", "role": "executive", "status": "active"},
    ]

    devices = generate_synthetic_devices([u["id"] for u in users])

    # Generate 120 synthetic protected assets
    assets: dict[str, str] = {}
    asset_contents: dict[str, str] = {}
    active_user_ids = ["alice", "bob", "carol", "dave", "frank"]

    for i in range(1, 121):
        asset_id = f"asset-synth-{i:03d}"
        owner = active_user_ids[(i - 1) % len(active_user_ids)]
        assets[asset_id] = owner
        asset_contents[asset_id] = (
            f"SYNTHETIC-CONFIDENTIAL-DOC-{i:03d}: Classification=RESTRICTED, Owner={owner}, "
            f"Checksum={hashlib.sha256(f'doc-{i}'.encode()).hexdigest()[:16]}"
        )

    services = [
        "Employee Portal",
        "Reports Service",
        "Billing Service",
        "Archive Service",
        "Identity Service"
    ]

    return SyntheticOrganization(
        users=users,
        devices=devices,
        assets=assets,
        asset_contents=asset_contents,
        services=services
    )


class IsolatedTestEnvironment:
    """Manages isolated SQLite databases and distributed node instances."""

    def __init__(self, env_id: str = "main_eval"):
        self.env_id = env_id
        self.state_dir = RUNTIME_ROOT / f"state_{env_id}"
        self.clean()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = get_db_path(self.state_dir)
        self.key_path = get_vault_key_path(self.state_dir)
        self.org = create_synthetic_organization()
        self.service: QuantumVaultService | None = None
        self.coordinator: ClusterCoordinator | None = None
        self.authority: SecurityAuthority | None = None
        self.nodes: dict[str, ServiceNode] = {}

    def clean(self) -> None:
        if self.state_dir.exists():
            try:
                shutil.rmtree(self.state_dir)
            except Exception:
                pass

    def initialize_vault(self) -> QuantumVaultService:
        """Initialize the core service and populate synthetic users, devices, and assets."""
        self.service = QuantumVaultService(state_dir=self.state_dir)
        
        # 1. Core setup
        owners = self.org.assets
        contents = self.org.asset_contents
        disabled = ["eve"]
        self.service.setup(
            owners=owners,
            contents=contents,
            disabled=disabled,
            key_material=f"synthetic-vault-key-seed-{self.env_id}"
        )

        # 2. Enroll devices
        conn = get_connection(self.db_path)
        dm = DeviceManager(conn)
        for dev in self.org.devices.values():
            if dev.status == "active":
                try:
                    dm.enroll_device(dev.owner, dev.device_id, dev.public_key_b64)
                except Exception:
                    pass
        conn.close()

        # 3. Initialize 3 mock distributed nodes via ClusterCoordinator
        self.coordinator = ClusterCoordinator(state_dir=self.state_dir, node_count=3)
        self.authority = self.coordinator.authority
        self.nodes = self.coordinator.nodes

        return self.service

    def close(self) -> None:
        if self.service:
            self.service.close()
        self.clean()


def make_security_event(
    event_id: str,
    actor: str,
    source_service: str,
    target_service: str,
    action: str,
    outcome: str = "allow",
    timestamp: str | None = None,
    event_time_utc: str | None = None,
    received_time_utc: str | None = None,
    source_clock_offset_ms: int = 0,
    clock_offset_ms: int = 0,
    role_before: str = "employee",
    role_after: str = "employee",
    approval_id: str | None = None,
    session_id: str | None = None,
    correlation_id: str | None = None,
    corrected_time_utc: str = "",
) -> SecurityEvent:
    t = event_time_utc or timestamp or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    rec = received_time_utc or t
    offset = source_clock_offset_ms or clock_offset_ms or 0
    return SecurityEvent(
        event_id=event_id,
        event_time_utc=t,
        received_time_utc=rec,
        source_clock_offset_ms=offset,
        actor=actor,
        source_service=source_service,
        target_service=target_service,
        action=action,
        role_before=role_before,
        role_after=role_after,
        outcome=outcome,
        approval_id=approval_id,
        session_id=session_id,
        correlation_id=correlation_id,
        corrected_time_utc=corrected_time_utc or t,
    )


def generate_unseen_telemetry(seed: int = 1337, count: int = 100) -> tuple[list[SecurityEvent], list[dict[str, Any]]]:
    """Generate an unseen synthetic telemetry stream with independent ground truth labels.
    
    Contains:
    - Normal access
    - Approved privilege changes
    - Unauthorized privilege elevations
    - Multi-hop lateral movement candidate sequences
    - Isolated denials
    - Clock skew events
    - Out-of-order delayed delivery
    """
    import random
    rng = random.Random(seed)

    events: list[SecurityEvent] = []
    ground_truth: list[dict[str, Any]] = []

    base_time_epoch = 1770000000  # Synthetic epoch

    # Sequence 1: 30 Normal employee access events
    for i in range(1, 31):
        t = base_time_epoch + i * 10
        iso_t = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
        evt_id = f"unseen-evt-{i:03d}"
        events.append(make_security_event(
            event_id=evt_id,
            timestamp=iso_t,
            actor="alice",
            source_service="portal",
            target_service="reports",
            action="read_report",
            outcome="allow",
            session_id="sess-normal-1",
            received_time_utc=iso_t,
            corrected_time_utc=iso_t
        ))
        ground_truth.append({
            "event_id": evt_id,
            "expected_label": "routine",
            "expected_rule": "RULE-009"
        })

    # Sequence 2: Approved Role Change (matched in approvals)
    t = base_time_epoch + 350
    iso_t = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
    evt_id = "unseen-evt-031"
    events.append(make_security_event(
        event_id=evt_id,
        timestamp=iso_t,
        actor="bob",
        source_service="portal",
        target_service="identity",
        action="role_change",
        outcome="allow",
        session_id="sess-approved-role",
        approval_id="apr-bob-role-01",
        received_time_utc=iso_t,
        corrected_time_utc=iso_t
    ))
    ground_truth.append({
        "event_id": evt_id,
        "expected_label": "approved_change",
        "expected_rule": "RULE-001"
    })

    # Sequence 3: Unauthorized Role Elevation
    t = base_time_epoch + 400
    iso_t = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
    evt_id = "unseen-evt-032"
    events.append(make_security_event(
        event_id=evt_id,
        timestamp=iso_t,
        actor="dave",
        source_service="portal",
        target_service="identity",
        action="role_change",
        outcome="allow",
        session_id="sess-unauth-role",
        approval_id=None,
        received_time_utc=iso_t,
        corrected_time_utc=iso_t
    ))
    ground_truth.append({
        "event_id": evt_id,
        "expected_label": "unexpected_role_change",
        "expected_rule": "RULE-002"
    })

    # Sequence 4: Review Following Unauthorized Role Transition
    t = base_time_epoch + 420
    iso_t = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
    evt_id = "unseen-evt-033"
    events.append(make_security_event(
        event_id=evt_id,
        timestamp=iso_t,
        actor="dave",
        source_service="reports",
        target_service="catalog",
        action="read_sensitive_catalog",
        outcome="allow",
        session_id="sess-unauth-role",
        received_time_utc=iso_t,
        corrected_time_utc=iso_t
    ))
    ground_truth.append({
        "event_id": evt_id,
        "expected_label": "review_after_role_change",
        "expected_rule": "RULE-003"
    })

    # Sequence 5: Candidate Lateral Movement Sequence (Hops across unexpected services)
    hops = [
        ("reports", "billing"),
        ("billing", "archive"),
        ("archive", "identity")
    ]
    for idx, (src, tgt) in enumerate(hops):
        t = base_time_epoch + 500 + idx * 15
        iso_t = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
        evt_id = f"unseen-evt-{34 + idx:03d}"
        events.append(make_security_event(
            event_id=evt_id,
            timestamp=iso_t,
            actor="attacker",
            source_service=src,
            target_service=tgt,
            action="cross_service_probe",
            outcome="deny",
            session_id="sess-lateral-hop",
            correlation_id="corr-lateral-1",
            received_time_utc=iso_t,
            corrected_time_utc=iso_t
        ))
        ground_truth.append({
            "event_id": evt_id,
            "expected_label": "lateral_movement_candidate",
            "expected_rule": "RULE-004"
        })

    # Sequence 6: Isolated Access Denial (Single uncoordinated denial)
    t = base_time_epoch + 600
    iso_t = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
    evt_id = "unseen-evt-037"
    events.append(make_security_event(
        event_id=evt_id,
        timestamp=iso_t,
        actor="carol",
        source_service="portal",
        target_service="billing",
        action="read_invoice",
        outcome="deny",
        session_id="sess-isolated-denial",
        correlation_id="corr-isolated",
        received_time_utc=iso_t,
        corrected_time_utc=iso_t
    ))
    ground_truth.append({
        "event_id": evt_id,
        "expected_label": "isolated_denial",
        "expected_rule": "RULE-006"
    })

    # Sequence 7: Clock Offset Normalization
    t = base_time_epoch + 700
    iso_t = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
    evt_id = "unseen-evt-038"
    events.append(make_security_event(
        event_id=evt_id,
        timestamp=iso_t,
        actor="frank",
        source_service="portal",
        target_service="reports",
        action="read_executive_brief",
        outcome="allow",
        session_id="sess-clock-skew",
        clock_offset_ms=2500,
        received_time_utc=iso_t,
        corrected_time_utc=iso_t
    ))
    ground_truth.append({
        "event_id": evt_id,
        "expected_label": "routine_clock_offset",
        "expected_rule": "RULE-008"
    })

    # Sequence 8: 62 Additional Routine and Benign events to reach 100 total
    for i in range(39, 101):
        t = base_time_epoch + 800 + i * 5
        iso_t = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
        evt_id = f"unseen-evt-{i:03d}"
        u = rng.choice(["alice", "bob", "carol", "frank"])
        events.append(make_security_event(
            event_id=evt_id,
            timestamp=iso_t,
            actor=u,
            source_service="portal",
            target_service="catalog",
            action="browse_catalog",
            outcome="allow",
            session_id=f"sess-bulk-{i}",
            received_time_utc=iso_t,
            corrected_time_utc=iso_t
        ))
        ground_truth.append({
            "event_id": evt_id,
            "expected_label": "routine",
            "expected_rule": "RULE-009"
        })

    return events, ground_truth
