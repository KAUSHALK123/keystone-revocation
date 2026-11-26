"""Dedicated 15-Step Judge Demonstration Mode executing live backend operations in isolated state."""
from pathlib import Path
import tempfile
import time
from typing import Any
from fastapi import APIRouter, Depends, HTTPException

from quantumvault.audit.checkpoints import CheckpointManager
from quantumvault.audit.verifier import AuditLogVerifier
from quantumvault.core.errors import CryptoError
from quantumvault.core.service import QuantumVaultService
from quantumvault.crypto.key_manager import get_vault_key_path, load_vault_key
from quantumvault.crypto.rotation import KeyRotationManager
from quantumvault.detection.engine import DetectionEngine
from quantumvault.detection.evaluator import DetectionEvaluator
from quantumvault.detection.ingestion import (
    load_approvals_from_json,
    load_events_from_csv,
    load_labels_from_csv,
)
from quantumvault.distributed.cluster import ClusterCoordinator
from quantumvault.iam.authentication import (
    DeviceAuthenticator,
    generate_device_keypair,
    sign_challenge,
)
from quantumvault.iam.device import DeviceManager
from quantumvault.iam.recovery import RecoveryManager
from quantumvault.messaging.handshake import MessagingHandshake
from quantumvault.messaging.session import MessagingSession
from quantumvault.storage.db import transaction
from quantumvault.vault.resources import ResourceVault
from quantumvault.web.authentication import verify_operator_auth
from quantumvault.web.schemas import JudgeDemoStatusResponse, JudgeDemoStepResult

router = APIRouter(prefix="/api/v1/judge-demo", tags=["Judge Demo Mode"])

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
PRACTICE_DIR = ROOT_DIR / "references" / "track4-toolkit" / "practice"

STEP_CATALOG = [
    {"step": 1, "title": "Authorized Employee Asset Access", "objective": "Access Control & AES-256-GCM", "expected": "Decision ALLOW for owner user-alex on brief-q4 and user-blair on ledger-ops.", "explanation": "Legitimate employee user-alex authenticates and reads protected asset 'brief-q4'."},
    {"step": 2, "title": "Post-Quantum Ephemeral Messaging Session", "objective": "Objectives 9 & 10 (ML-KEM-768)", "expected": "ML-KEM-768 handshake completes, AEAD message decrypts, and ephemeral secret is cleared.", "explanation": "Alice and Bob establish an ephemeral ML-KEM-768 session, send AEAD-encrypted data, and zeroize ephemeral keys."},
    {"step": 3, "title": "Suspicious Privilege Escalation Ingested", "objective": "Objective 6 (Telemetry Ingestion)", "expected": "22 practice telemetry events and approvals load deterministically with F1=1.0.", "explanation": "Security telemetry ingests an unapproved role transition from viewer to operator without a change approval."},
    {"step": 4, "title": "Threat Radar Detects Unexpected Permissions", "objective": "Objective 6 (Deterministic Rules)", "expected": "Deterministic engine creates incidents for RULE-002 and RULE-003.", "explanation": "Deterministic engine triggers RULE-002 (unexpected_role_change) and RULE-003 (review_after_role_change)."},
    {"step": 5, "title": "Lateral Movement Sequence Detected", "objective": "Objective 7 (Service Graph)", "expected": "RULE-004 flags multi-hop lateral sequence across evt-010..012 with Accuracy=1.0.", "explanation": "Correlated multi-hop denied transitions across unexpected services trigger RULE-004 without false compromise."},
    {"step": 6, "title": "Compromised Device Revocation Committed", "objective": "Objective 2 (IAM Revocation)", "expected": "dev-alex-orig revoked durably while unaffected peer user-blair keeps access.", "explanation": "Compromised device dev-alex-orig is durably revoked in SQLite WAL while peer user-blair remains unaffected."},
    {"step": 7, "title": "Revocation Broadcast Across Connected Nodes", "objective": "Objective 2 (Cluster Epoch Sync)", "expected": "Authority increments epoch and all 3 online nodes confirm probe denial.", "explanation": "SecurityAuthority advances monotonic epoch and propagates revocation to connected nodes, verified via real probes."},
    {"step": 8, "title": "Partitioned Node Enforces Fail-Closed Denial", "objective": "Objective 2 (Partition Safety)", "expected": "Partitioned node-c refuses requests fail-closed (node_offline_fail_closed).", "explanation": "Disconnected node-c cannot verify freshness with authority and refuses access (node_offline_fail_closed)."},
    {"step": 9, "title": "Zero-Downtime Key Rotation (v1 -> v2)", "objective": "Objective 1 (Key Lifecycle)", "expected": "Master key rotates v1->v2, assets rewrap atomically, authorized reads continue.", "explanation": "KeyRotationManager promotes v2 to active, moves v1 to grace_period, and rewraps protected assets."},
    {"step": 10, "title": "Retired Key Rejected After Cutoff", "objective": "Objective 1 (Cutoff Enforcement)", "expected": "Attempting to access retired key v1 past cutoff raises CryptoError.", "explanation": "Once v1 passes cutoff into retired status, decryption using v1 raises CryptoError across the vault."},
    {"step": 11, "title": "Partitioned Node Reconnects & Synchronizes", "objective": "Objective 2 (State Reconciliation)", "expected": "node-c syncs epoch & revocations before serving, then denies dev-alex-orig.", "explanation": "Node-c reconnects, syncs missed revocations and current epoch from authority, and enforces authoritative denial."},
    {"step": 12, "title": "Legitimate User Recovers via Single-Use Code", "objective": "Objective 2 (Emergency Recovery)", "expected": "user-alex consumes recovery code to enroll dev-alex-rep and regains read access.", "explanation": "user-alex consumes a salted CSPRNG recovery code to enroll replacement device dev-alex-rep and regains access."},
    {"step": 13, "title": "Compromised Credentials Remain Blocked", "objective": "Objective 3 (Anti-Resurrection)", "expected": "Old device dev-alex-orig cannot authenticate or request challenges (anti-resurrection).", "explanation": "Original compromised device dev-alex-orig remains permanently revoked and fails challenge authentication."},
    {"step": 14, "title": "Isolated Audit Tampering Caught by Verifier", "objective": "Objective 5 (Hash Chain & HMAC)", "expected": "AuditLogVerifier detects single flipped DB decision and flags status=tampered.", "explanation": "Modifying an audit row in an isolated copy breaks SHA-256 chaining and is immediately flagged by AuditLogVerifier."},
    {"step": 15, "title": "Final Security Evidence & Metrics Summary", "objective": "All 12 Hackathon Objectives", "expected": "Isolated audit log verifies valid across 14 prior steps with cluster & detection intact.", "explanation": "Consolidates verified outputs from the live isolated run across cryptography, cluster, detection, and audit."},
]


class _JudgeDemoRunner:
    """Holds isolated, resettable state for the 15-step interactive Judge Demo."""

    def __init__(self) -> None:
        self.temp_dir: tempfile.TemporaryDirectory | None = None
        self.state_dir: Path | None = None
        self.service: QuantumVaultService | None = None
        self.coord: ClusterCoordinator | None = None
        self.active: bool = False
        self.current_step: int = 0
        self.completed_steps: list[JudgeDemoStepResult] = []
        self.ctx: dict[str, Any] = {}

    def reset(self) -> None:
        if self.coord is not None:
            try:
                self.coord.close()
            except Exception:
                pass
            self.coord = None
        if self.service is not None:
            try:
                self.service.close()
            except Exception:
                pass
            self.service = None
        if self.temp_dir is not None:
            try:
                self.temp_dir.cleanup()
            except Exception:
                pass
            self.temp_dir = None
        self.state_dir = None
        self.active = False
        self.current_step = 0
        self.completed_steps = []
        self.ctx = {}

    def start(self) -> None:
        self.reset()
        self.temp_dir = tempfile.TemporaryDirectory(prefix="qv-judge-demo-")
        self.state_dir = Path(self.temp_dir.name)
        self.service = QuantumVaultService(state_dir=self.state_dir)
        self.service.setup(
            owners={"brief-q4": "user-alex", "ledger-ops": "user-blair"},
            contents={
                "brief-q4": "Q4 Confidential Strategic Acquisition Plan",
                "ledger-ops": "Blair Independent Treasury Ledger",
            },
            disabled=[],
            key_material="judge-demo-isolated-seed",
        )
        dev_mgr = DeviceManager(self.service.conn)
        sk_orig, pk_orig = generate_device_keypair()
        dev_mgr.enroll_device("user-alex", "dev-alex-orig", pk_orig)
        sk_blair, pk_blair = generate_device_keypair()
        dev_mgr.enroll_device("user-blair", "dev-blair-orig", pk_blair)
        codes = RecoveryManager(self.service.conn).generate_recovery_codes("user-alex", count=2)

        self.ctx = {
            "sk_alex_orig": sk_orig,
            "pk_alex_orig": pk_orig,
            "sk_blair": sk_blair,
            "recovery_codes": codes,
        }
        self.active = True

    def execute_next(self) -> JudgeDemoStepResult:
        if not self.active:
            self.start()
        if self.current_step >= 15:
            raise HTTPException(status_code=400, detail="All 15 demo steps are already completed. Reset to run again.")

        step_num = self.current_step + 1
        meta = STEP_CATALOG[step_num - 1]
        t0 = time.perf_counter()
        result_data: dict[str, Any] = {}
        status_str = "PASS"

        assert self.service is not None and self.state_dir is not None
        svc = self.service

        try:
            if step_num == 1:
                r_alex = svc.read("user-alex", "brief-q4", "demo-req-01")
                r_blair = svc.read("user-blair", "ledger-ops", "demo-req-02")
                assert r_alex["decision"] == "allow" and r_blair["decision"] == "allow"
                result_data = {"actor": "user-alex", "asset": "brief-q4", "decision": r_alex["decision"], "peer_decision": r_blair["decision"]}

            elif step_num == 2:
                hs = MessagingHandshake()
                sk_a, pk_a = generate_device_keypair()
                sk_b, pk_b = generate_device_keypair()
                offer = hs.generate_responder_offer("bob", "dev-bob", sk_b)
                init_p, k_as, k_ar = hs.initiate_session("alice", "dev-alice", sk_a, offer, pk_b)
                k_br, k_bs = hs.complete_responder(offer, init_p, pk_a)
                sess_a = MessagingSession(offer["session_id"], "alice", "dev-alice", "bob", "dev-bob", k_as, k_ar)
                sess_b = MessagingSession(offer["session_id"], "bob", "dev-bob", "alice", "dev-alice", k_bs, k_br)
                env = sess_a.send_message("Verified PQ channel established")
                plain = sess_b.receive_message(env).decode("utf-8")
                sess_a.close()
                sess_b.close()
                result_data = {"session_id": offer["session_id"], "decrypted_message": plain, "ephemeral_key_zeroized": offer.get("_ephemeral_sk_bytes") is None}

            elif step_num == 3:
                events = load_events_from_csv(PRACTICE_DIR / "events.csv")
                approvals = load_approvals_from_json(PRACTICE_DIR / "approvals.json")
                labels = load_labels_from_csv(PRACTICE_DIR / "labels.csv")
                engine = DetectionEngine(approval_registry=approvals)
                classifications = engine.evaluate_events(events)
                metrics = DetectionEvaluator(labels).evaluate(classifications)
                self.ctx["det_engine"] = engine
                self.ctx["det_classifications"] = classifications
                self.ctx["det_metrics"] = metrics
                ev8 = next(e for e in events if e.event_id == "evt-008")
                result_data = {"ingested_events": len(events), "target_event": ev8.event_id, "actor": ev8.actor, "transition": f"{ev8.role_before}->{ev8.role_after}", "approval_id": ev8.approval_id}

            elif step_num == 4:
                engine = self.ctx["det_engine"]
                inc_role = [i for i in engine.incidents if i.incident_type in ("unexpected_role_change", "review_after_role_change")]
                assert len(inc_role) >= 1
                result_data = {"incidents_triggered": len(inc_role), "rules": [i.rule_id for i in inc_role], "actors": [i.actor_id for i in inc_role]}

            elif step_num == 5:
                engine = self.ctx["det_engine"]
                metrics = self.ctx["det_metrics"]
                lat = [i for i in engine.incidents if i.incident_type == "lateral_movement_candidate"]
                assert len(lat) >= 1
                result_data = {"lateral_incident_id": lat[0].incident_id, "evidence_events": lat[0].evidence_event_ids, "f1_score": metrics.f1_score, "exact_accuracy": metrics.exact_accuracy}

            elif step_num == 6:
                dev_mgr = DeviceManager(svc.conn)
                dev_mgr.revoke_device("dev-alex-orig", reason="judge_demo_compromise")
                svc.conn.commit()
                peer_ok = svc.read("user-blair", "ledger-ops", "demo-req-peer")
                assert not dev_mgr.is_device_active("dev-alex-orig") and peer_ok["decision"] == "allow"
                result_data = {"revoked_device": "dev-alex-orig", "device_active": False, "unaffected_peer_decision": peer_ok["decision"]}

            elif step_num == 7:
                self.coord = ClusterCoordinator(state_dir=self.state_dir, node_count=3)
                # Partition node-c only in step 8; all 3 online now
                b_res = self.coord.broadcast_revocation("dev-alex-orig", entity_type="device", reason="judge_demo_compromise")
                assert len(b_res["confirmed_nodes"]) == 3
                result_data = {"epoch": b_res["epoch"], "confirmed_nodes": b_res["confirmed_nodes"], "propagation_ms": b_res["total_propagation_ms"]}

            elif step_num == 8:
                coord = self.coord
                coord.partition_node("node-c")
                node_c = coord.get_node("node-c")
                res_c = node_c.read("user-blair", "ledger-ops", "demo-req-part")
                assert res_c["decision"] == "deny" and res_c.get("rule") == "node_offline_fail_closed"
                result_data = {"partitioned_node": "node-c", "decision": res_c["decision"], "rule": res_c.get("rule")}

            elif step_num == 9:
                key = load_vault_key(get_vault_key_path(self.state_dir))
                rot = KeyRotationManager(svc.conn, key)
                rot_res = rot.rotate_key("v2", grace_seconds=30.0, rewrap_assets=True)
                self.coord.sync_all()
                r_v2 = svc.read("user-blair", "ledger-ops", "demo-req-v2")
                assert rot_res["active_version"] == "v2" and r_v2["decision"] == "allow"
                result_data = {"previous_version": rot_res["previous_version"], "active_version": rot_res["active_version"], "rewrapped_count": rot_res["rewrapped_count"], "duration_ms": rot_res["rotation_duration_ms"]}

            elif step_num == 10:
                key = load_vault_key(get_vault_key_path(self.state_dir))
                rot = KeyRotationManager(svc.conn, key)
                rot.expire_cutoff("v1")
                rejected = False
                try:
                    rot.get_key_for_version("v1")
                except CryptoError:
                    rejected = True
                assert rejected
                result_data = {"retired_version": "v1", "v1_rejected_after_cutoff": rejected}

            elif step_num == 11:
                coord = self.coord
                coord.reconnect_node("node-c")
                node_c = coord.get_node("node-c")
                denied_orig = node_c.read("user-alex", "brief-q4", "demo-req-reconn", device_id="dev-alex-orig")
                assert node_c.is_healthy() and denied_orig["decision"] == "deny"
                result_data = {"reconnected_node": "node-c", "synced_epoch": node_c.current_epoch, "compromised_device_decision": denied_orig["decision"]}

            elif step_num == 12:
                rec_mgr = RecoveryManager(svc.conn)
                _, pk_rep = generate_device_keypair()
                rec_res = rec_mgr.recover_and_replace_device("user-alex", self.ctx["recovery_codes"][0], "dev-alex-rep", pk_rep)
                node_a = self.coord.get_node("node-a")
                r_rep = node_a.read("user-alex", "brief-q4", "demo-req-rep", device_id="dev-alex-rep")
                assert rec_res["replacement_confirmed"] and r_rep["decision"] == "allow"
                result_data = {"recovered_actor": "user-alex", "new_device": "dev-alex-rep", "read_decision": r_rep["decision"]}

            elif step_num == 13:
                dev_mgr = DeviceManager(svc.conn)
                auth = DeviceAuthenticator(svc.conn)
                auth_rejected = False
                try:
                    auth.create_challenge("dev-alex-orig", purpose="read")
                except Exception:
                    auth_rejected = True
                assert not dev_mgr.is_device_active("dev-alex-orig") and auth_rejected
                result_data = {"compromised_device": "dev-alex-orig", "is_active": False, "challenge_rejected": auth_rejected}

            elif step_num == 14:
                # Run tamper test in a separate isolated copy so main demo state remains clean
                with tempfile.TemporaryDirectory() as td_tamper:
                    tamper_svc = QuantumVaultService(state_dir=Path(td_tamper))
                    try:
                        tamper_svc.setup({"a1": "user-alex"}, {"a1": "Secret"}, [], "tamper-seed")
                        tamper_svc.read("user-alex", "a1", "t-req-1")
                        tamper_svc.read("intruder", "a1", "t-req-2")
                        chk = CheckpointManager(tamper_svc.conn, external_file_path=Path(td_tamper) / "ext_chk.json")
                        chk.create_checkpoint("chk-tamper-demo")
                        with transaction(tamper_svc.conn):
                            tamper_svc.conn.execute("UPDATE audit_events SET decision = 'allow' WHERE request_id = 't-req-2';")
                        report = AuditLogVerifier(tamper_svc.conn, external_file_path=Path(td_tamper) / "ext_chk.json").verify()
                        assert report["status"] == "tampered"
                        result_data = {"audit_status": report["status"], "error_type": report["first_inconsistency"]["error_type"], "tampered_request_id": report["first_inconsistency"]["request_id"]}
                    finally:
                        tamper_svc.close()

            elif step_num == 15:
                verifier = AuditLogVerifier(svc.conn)
                audit_ok = verifier.verify()
                metrics = self.ctx["det_metrics"]
                result_data = {
                    "steps_completed": 14,
                    "audit_chain_status": audit_ok["status"],
                    "audit_verified_records": audit_ok["verified_records"],
                    "cluster_epoch": self.coord.authority.get_current_epoch(),
                    "active_key_version": svc.app_state.get("active_key_version"),
                    "detection_f1": metrics.f1_score,
                    "isolated_from_adapter": True,
                }
        except Exception as e:
            status_str = "FAIL"
            result_data = {"error": str(e)}

        duration_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        actual_outcome = (
            f"FAILED: {result_data.get('error', 'unknown_error')}"
            if status_str != "PASS"
            else ", ".join(f"{k}={v}" for k, v in list(result_data.items())[:4])
        )
        step_res = JudgeDemoStepResult(
            step=step_num,
            total_steps=15,
            title=meta["title"],
            objective=meta["objective"],
            explanation=meta["explanation"],
            expected_outcome=meta["expected"],
            actual_outcome=actual_outcome,
            status=status_str,
            duration_ms=duration_ms,
            result=result_data,
        )
        self.current_step = step_num
        self.completed_steps.append(step_res)
        return step_res


_DEMO_RUNNER = _JudgeDemoRunner()


@router.get("/status", response_model=JudgeDemoStatusResponse)
def get_judge_demo_status(auth: dict = Depends(verify_operator_auth)):
    return JudgeDemoStatusResponse(
        active=_DEMO_RUNNER.active,
        current_step=_DEMO_RUNNER.current_step,
        total_steps=15,
        completed_steps=_DEMO_RUNNER.completed_steps,
        step_catalog=STEP_CATALOG,
    )


@router.post("/start", response_model=JudgeDemoStatusResponse)
def start_judge_demo(auth: dict = Depends(verify_operator_auth)):
    _DEMO_RUNNER.start()
    return get_judge_demo_status(auth=auth)


@router.post("/next", response_model=JudgeDemoStepResult)
def next_judge_demo_step(auth: dict = Depends(verify_operator_auth)):
    return _DEMO_RUNNER.execute_next()


@router.post("/reset", response_model=JudgeDemoStatusResponse)
def reset_judge_demo(auth: dict = Depends(verify_operator_auth)):
    _DEMO_RUNNER.reset()
    return get_judge_demo_status(auth=auth)
