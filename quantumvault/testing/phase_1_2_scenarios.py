"""23-Step Comprehensive End-to-End Failure and Security Resilience Scenario for Phase 1.2."""
from dataclasses import dataclass, field
from pathlib import Path
import tempfile
import time
from typing import Any

from quantumvault.audit.checkpoints import CheckpointManager
from quantumvault.audit.verifier import AuditLogVerifier
from quantumvault.backup.backup_manager import BackupManager
from quantumvault.backup.restore import BackupRestoreManager
from quantumvault.config import get_vault_key_path
from quantumvault.core.errors import StateError
from quantumvault.core.service import QuantumVaultService
from quantumvault.crypto.key_manager import load_vault_key
from quantumvault.crypto.rotation import KeyRotationManager
from quantumvault.distributed.cluster import ClusterCoordinator
from quantumvault.iam.authentication import (
    DeviceAuthenticator,
    generate_device_keypair,
    sign_challenge,
)
from quantumvault.iam.device import DeviceManager
from quantumvault.iam.recovery import RecoveryManager
from quantumvault.storage.db import get_connection, transaction


@dataclass
class ScenarioResult:
    steps_passed: int = 0
    total_steps: int = 23
    step_details: list[dict[str, Any]] = field(default_factory=list)
    success: bool = False
    execution_time_ms: float = 0.0


class Phase12GrandScenario:
    """Executes the full 23-step headless adversarial security resilience scenario."""

    def __init__(self, state_dir: Path | None = None):
        self._temp_dir = None
        if state_dir is None:
            self._temp_dir = tempfile.TemporaryDirectory()
            self.state_dir = Path(self._temp_dir.name)
        else:
            self.state_dir = state_dir

    def run(self) -> ScenarioResult:
        t_start = time.perf_counter()
        result = ScenarioResult()

        def record_step(step_num: int, title: str, status: str, details: Any = None):
            result.step_details.append({
                "step": step_num,
                "title": title,
                "status": status,
                "details": details or {}
            })
            if status == "PASS":
                result.steps_passed += 1

        try:
            # Step 1: Clean setup of QuantumVault
            service = QuantumVaultService(state_dir=self.state_dir)
            setup_res = service.setup(
                owners={"asset-fin-1": "analyst-1", "asset-peer-1": "peer-1"},
                contents={"asset-fin-1": "Sensitive Financials Q4", "asset-peer-1": "Peer Engineering Specs"},
                disabled=[],
                key_material="grand-scenario-master-secret-key-material"
            )
            assert setup_res["ready"] is True
            record_step(1, "Clean setup and isolated initialization", "PASS")

            # Step 2: Enroll multiple devices for analyst-1 (phone-1 and laptop-1)
            conn = get_connection(service.db_path)
            dev_mgr = DeviceManager(conn)
            priv_phone, pub_phone = generate_device_keypair()
            priv_laptop, pub_laptop = generate_device_keypair()
            dev_mgr.enroll_device("analyst-1", "phone-1", pub_phone)
            dev_mgr.enroll_device("analyst-1", "laptop-1", pub_laptop)
            assert dev_mgr.is_device_active("phone-1")
            assert dev_mgr.is_device_active("laptop-1")
            record_step(2, "Multi-device enrollment with Ed25519 keys", "PASS")

            # Step 3: Generate high-entropy single-use recovery codes
            rec_mgr = RecoveryManager(conn)
            recovery_codes = rec_mgr.generate_recovery_codes("analyst-1", count=3)
            assert len(recovery_codes) == 3
            record_step(3, "Generate salted recovery credentials", "PASS", {"codes_count": len(recovery_codes)})

            # Step 4: Challenge-response proof-of-possession
            auth = DeviceAuthenticator(conn, ttl_seconds=30.0)
            chal = auth.create_challenge("phone-1")["challenge"]
            sig = sign_challenge(priv_phone, chal)
            assert auth.verify_response("phone-1", chal, sig) is True
            record_step(4, "Challenge-response device authentication", "PASS")

            # Step 5: Initialize 3-node cluster coordinator
            service.close()
            cluster = ClusterCoordinator(state_dir=self.state_dir, node_count=3)
            assert len(cluster.nodes) == 3
            record_step(5, "Cluster coordinator 3-node initialization", "PASS")

            # Step 6: Authorized read on Node A with phone-1
            node_a = cluster.get_node("node-a")
            res_6 = node_a.read("analyst-1", "asset-fin-1", "req-step-6", device_id="phone-1")
            assert res_6["decision"] == "allow"
            assert res_6["body"] == "Sensitive Financials Q4"
            record_step(6, "Authorized read on Node A", "PASS")

            # Step 7: Authorized read on Node B with laptop-1
            node_b = cluster.get_node("node-b")
            res_7 = node_b.read("analyst-1", "asset-fin-1", "req-step-7", device_id="laptop-1")
            assert res_7["decision"] == "allow"
            record_step(7, "Authorized read on Node B", "PASS")

            # Step 8: Network partition on Node C
            cluster.partition_node("node-c")
            node_c = cluster.get_node("node-c")
            assert node_c.status == "offline"
            record_step(8, "Simulate partition on Node C", "PASS")

            # Step 9: Fail-closed denial on partitioned Node C
            res_9 = node_c.read("analyst-1", "asset-fin-1", "req-step-9")
            assert res_9["decision"] == "deny"
            assert res_9.get("rule") == "node_offline_fail_closed"
            record_step(9, "Fail-closed enforcement on offline Node C", "PASS")

            # Step 10: Age Node B's heartbeat past 5000ms threshold
            node_b.simulate_heartbeat_timeout(seconds_ago=10.0)
            res_10 = node_b.read("analyst-1", "asset-fin-1", "req-step-10")
            assert res_10["decision"] == "deny"
            record_step(10, "Aged heartbeat (>5.0s) triggers fail-closed isolation", "PASS")

            # Step 11: Refresh Node B's heartbeat
            node_b.send_heartbeat()
            assert node_b.is_healthy() is True
            res_11 = node_b.read("analyst-1", "asset-fin-1", "req-step-11")
            assert res_11["decision"] == "allow"
            record_step(11, "Heartbeat recovery restores Node B service", "PASS")

            # Step 12: Rotate master key from V1 to V2 with rewrapping
            kek = load_vault_key(get_vault_key_path(self.state_dir))
            rot_mgr = KeyRotationManager(cluster.authority.conn, kek)
            rot_res = rot_mgr.rotate_key("v2", grace_seconds=60.0, rewrap_assets=True)
            assert rot_res["active_version"] == "v2"
            assert rot_res["rewrapped_count"] >= 1
            record_step(12, "Key rotation V1 -> V2 with asset rewrapping", "PASS", rot_res)

            # Step 13: Rewrapped assets decrypt cleanly
            cluster.sync_all()
            res_13 = node_a.read("analyst-1", "asset-fin-1", "req-step-13")
            assert res_13["decision"] == "allow"
            assert res_13["body"] == "Sensitive Financials Q4"
            record_step(13, "Rewrapped assets decrypt cleanly under V2", "PASS")

            # Step 14: Broadcast revocation for lost phone-1
            bcast_res = cluster.broadcast_revocation("phone-1", entity_type="device")
            record_step(14, "Broadcast device revocation for phone-1", "PASS", bcast_res)

            # Step 15: Measure propagation latency across online nodes
            assert bcast_res["nodes_updated"] >= 2
            assert bcast_res["nodes_offline"] >= 1  # Node C is offline
            record_step(15, "Propagation latency telemetried per node", "PASS", {
                "latencies_ms": bcast_res["node_latencies_ms"],
                "total_ms": bcast_res["total_propagation_ms"]
            })

            # Step 16: Immediate read denial on phone-1 across online nodes
            res_16_a = node_a.read("analyst-1", "asset-fin-1", "req-step-16-a", device_id="phone-1")
            res_16_b = node_b.read("analyst-1", "asset-fin-1", "req-step-16-b", device_id="phone-1")
            assert res_16_a["decision"] == "deny"
            assert res_16_b["decision"] == "deny"
            record_step(16, "Immediate denial on revoked device phone-1", "PASS")

            # Step 17: Unaffected device laptop-1 and peer retain access
            res_17_laptop = node_a.read("analyst-1", "asset-fin-1", "req-step-17-lap", device_id="laptop-1")
            res_17_peer = node_a.read("peer-1", "asset-peer-1", "req-step-17-peer")
            assert res_17_laptop["decision"] == "allow"
            assert res_17_peer["decision"] == "allow"
            record_step(17, "Unaffected devices and peers retain authorized access", "PASS")

            # Step 18: Hot database backup (Snapshot 1)
            backup_mgr = BackupManager(state_dir=self.state_dir)
            backup_path = self.state_dir / "backups" / "grand_snapshot.qvb"
            backup_meta = backup_mgr.create_backup(backup_path)
            assert backup_path.exists()
            record_step(18, "Hot authenticated AES-GCM backup creation", "PASS", backup_meta)

            # Step 19: Advance epoch with another revocation
            adv_res = cluster.broadcast_revocation("peer-1", entity_type="actor")
            assert adv_res["epoch"] > backup_meta["cluster_epoch"]
            record_step(19, "Epoch advanced past backup snapshot epoch", "PASS", {"new_epoch": adv_res["epoch"]})

            # Step 20: Rollback attack rejection
            restore_mgr = BackupRestoreManager(state_dir=self.state_dir)
            rollback_rejected = False
            try:
                restore_mgr.verify_and_restore(backup_path, force_allow_rollback=False)
            except StateError:
                rollback_rejected = True
            assert rollback_rejected is True
            record_step(20, "Anti-rollback defense rejects stale backup", "PASS")

            # Step 21: Recovery code re-enrollment (tablet-1 replaces phone-1)
            priv_tablet, pub_tablet = generate_device_keypair()
            rec_res = rec_mgr.recover_and_replace_device(
                actor_id="analyst-1",
                recovery_code=recovery_codes[0],
                new_device_id="tablet-1",
                new_public_key_b64=pub_tablet
            )
            assert rec_res["replacement_confirmed"] is True
            # Reusing same code must fail
            assert rec_mgr.verify_and_consume("analyst-1", recovery_codes[0]) is False
            record_step(21, "Single-use recovery code consumption and device replacement", "PASS")

            # Step 22: Inject audit tampering and detect via verifier
            svc_audit = QuantumVaultService(state_dir=self.state_dir)
            verifier = AuditLogVerifier(svc_audit.conn)
            # Pristine audit log verifies valid
            initial_rep = verifier.verify()
            assert initial_rep["status"] == "valid", f"Audit initially invalid: {initial_rep}"
            # Maliciously alter a past decision
            with transaction(svc_audit.conn):
                cur = svc_audit.conn.execute("UPDATE audit_events SET decision = 'deny' WHERE request_id = 'req-step-6';")
                assert cur.rowcount == 1, "Failed to update target audit event"
            tampered_report = verifier.verify()
            assert tampered_report["status"] == "tampered", f"Expected tampered, got {tampered_report}"
            assert tampered_report["first_inconsistency"]["error_type"] == "hash_mismatch"
            # Restore audit integrity
            with transaction(svc_audit.conn):
                svc_audit.conn.execute("UPDATE audit_events SET decision = 'allow' WHERE request_id = 'req-step-6';")
            restored_rep = verifier.verify()
            assert restored_rep["status"] == "valid", f"Failed to restore audit integrity: {restored_rep}"
            svc_audit.close()
            record_step(22, "Audit tampering detection via cryptographic hash chain", "PASS")

            # Step 23: Reconnect Node C, sync cluster, create checkpoint, verify invariants
            cluster.reconnect_node("node-c")
            assert cluster.get_node("node-c").is_healthy() is True
            chk_mgr = CheckpointManager(cluster.authority.conn)
            checkpoint = chk_mgr.create_checkpoint("final-grand-checkpoint")
            assert checkpoint is not None
            assert chk_mgr.verify_checkpoint(checkpoint) is True
            cluster.close()
            record_step(23, "Reconnect node, create signed checkpoint, verify invariants", "PASS")

            result.success = (result.steps_passed == result.total_steps)

        finally:
            if self._temp_dir is not None:
                try:
                    self._temp_dir.cleanup()
                except Exception:
                    pass

        t_end = time.perf_counter()
        result.execution_time_ms = round((t_end - t_start) * 1000.0, 2)
        return result
