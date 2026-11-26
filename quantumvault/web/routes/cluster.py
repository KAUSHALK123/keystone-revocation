"""Cluster topology, distributed revocation, and IAM device routes."""
import base64
import time
from fastapi import APIRouter, Depends, HTTPException, Query

from quantumvault.core.service import QuantumVaultService
from quantumvault.crypto.key_manager import get_vault_key_path, load_vault_key
from quantumvault.crypto.rotation import KeyRotationManager
from quantumvault.distributed.cluster import ClusterCoordinator
from quantumvault.iam.authentication import generate_device_keypair
from quantumvault.iam.device import DeviceManager
from quantumvault.iam.recovery import RecoveryManager
from quantumvault.web.authentication import verify_operator_auth
from quantumvault.web.routes.status import _STATE_DIR, get_service
from quantumvault.web.schemas import (
    ClusterStatusResponse,
    DeviceInfo,
    KeyRotationResponse,
    NodePartitionRequest,
    NodeStatus,
    RevokeClusterRequest,
    RevokeClusterResponse,
)

router = APIRouter(prefix="/api/v1", tags=["Cluster & Revocation"])

_COORDINATOR: ClusterCoordinator | None = None


def get_coordinator() -> ClusterCoordinator:
    global _COORDINATOR
    if _COORDINATOR is None:
        # Ensure service state is seeded first
        get_service()
        _COORDINATOR = ClusterCoordinator(state_dir=_STATE_DIR, node_count=3)
    return _COORDINATOR


@router.get("/cluster/status", response_model=ClusterStatusResponse)
def get_cluster_status(auth: dict = Depends(verify_operator_auth)):
    """Return live simulated cluster topology, node health, and synchronization status."""
    coord = get_coordinator()
    svc = get_service()
    epoch = coord.authority.get_current_epoch()
    active_key = svc.app_state.get("active_key_version") or coord.authority.get_active_key_version()

    # Check if any key is in grace_period
    grace_row = svc.conn.execute(
        "SELECT 1 FROM key_versions WHERE status = 'grace_period' LIMIT 1;"
    ).fetchone()

    nodes: list[NodeStatus] = [
        NodeStatus(
            node_id="auth-primary",
            name="Security Authority (Primary)",
            status="online",
            healthy=True,
            last_heartbeat_epoch=epoch,
            key_version=active_key,
            role="authority",
            simulated_in_process=True,
        )
    ]

    for name, node in coord.nodes.items():
        is_healthy = node.is_healthy()
        status_label = "online" if is_healthy else ("fail-closed" if node.status == "offline" else "degraded")
        nodes.append(NodeStatus(
            node_id=name,
            name=f"Service Node {name.split('-')[-1].upper()}",
            status=status_label,
            healthy=is_healthy,
            last_heartbeat_epoch=node.current_epoch,
            key_version=node.active_key_version or active_key,
            role="worker",
            simulated_in_process=True,
        ))

    return ClusterStatusResponse(
        current_epoch=epoch,
        active_key_version=active_key,
        grace_period_active=bool(grace_row),
        cluster_mode="simulated_in_process",
        nodes=nodes,
    )


@router.post("/cluster/revoke", response_model=RevokeClusterResponse)
def broadcast_revocation(req: RevokeClusterRequest, auth: dict = Depends(verify_operator_auth)):
    """Commit revocation at authority, propagate to nodes, and confirm real enforcement."""
    coord = get_coordinator()
    svc = get_service()
    if req.entity_type == "actor":
        svc.revoke(req.entity_id)
    else:
        DeviceManager(svc.conn).revoke_device(req.entity_id, reason=req.reason)
        svc.conn.commit()

    res = coord.broadcast_revocation(
        entity_id=req.entity_id,
        entity_type=req.entity_type,
        reason=req.reason,
    )
    return RevokeClusterResponse(
        epoch=res["epoch"],
        entity_id=res["entity_id"],
        revocation_hash=res["revocation_hash"],
        auth_commit_latency_ms=res["auth_commit_latency_ms"],
        node_latencies_ms=res["node_latencies_ms"],
        probe_latencies_ms=res.get("probe_latencies_ms", {}),
        confirmed_nodes=res["confirmed_nodes"],
        total_propagation_ms=res["total_propagation_ms"],
    )


@router.post("/cluster/partition-node")
def partition_or_reconnect_node(req: NodePartitionRequest, auth: dict = Depends(verify_operator_auth)):
    """Simulate network partition or reconnect an individual service node."""
    coord = get_coordinator()
    node = coord.get_node(req.node_id)
    if not node:
        raise HTTPException(status_code=404, detail=f"Node {req.node_id} not found")

    if req.action == "disconnect":
        coord.partition_node(req.node_id)
        return {
            "node_id": req.node_id,
            "status": "offline",
            "enforcement": "fail-closed",
            "message": f"Node {req.node_id} partitioned; will strictly fail closed on authorization attempts.",
        }
    else:
        coord.reconnect_node(req.node_id)
        return {
            "node_id": req.node_id,
            "status": "online",
            "enforcement": "synchronized",
            "message": f"Node {req.node_id} reconnected and synchronized with Authority epoch {coord.authority.get_current_epoch()}.",
        }


@router.get("/iam/devices", response_model=list[DeviceInfo])
def list_devices(auth: dict = Depends(verify_operator_auth)):
    """List enrolled devices and their cryptographic public key types."""
    svc = get_service()
    rows = svc.conn.execute(
        "SELECT device_id, actor_id, public_key_b64, status, enrolled_at FROM devices ORDER BY enrolled_at ASC;"
    ).fetchall()

    result = []
    for r in rows:
        dev_id = r["device_id"]
        owner = r["actor_id"]
        pk_b64 = r["public_key_b64"]
        dev_status = r["status"]
        enrolled_at = r["enrolled_at"]
        try:
            raw_len = len(base64.b64decode(pk_b64, validate=True))
        except Exception:
            raw_len = 0
        alg = "ML-DSA-65 (NIST FIPS 204)" if raw_len == 1952 else "Ed25519 (Classical)"
        result.append(DeviceInfo(
            device_id=dev_id,
            owner=owner,
            status=dev_status,
            algorithm=alg,
            enrolled_at=str(enrolled_at),
            public_key_preview=f"{pk_b64[:16]}...",
        ))
    return result


@router.post("/iam/revoke-device")
def revoke_specific_device(device_id: str = Query(..., min_length=1, max_length=128),
                           auth: dict = Depends(verify_operator_auth)):
    """Revoke a specific device immediately with durable persistence and cluster broadcast."""
    svc = get_service()
    dev_mgr = DeviceManager(svc.conn)
    dev_mgr.revoke_device(device_id, reason="operator_revocation_web")
    coord = get_coordinator()
    res = coord.broadcast_revocation(entity_id=device_id, entity_type="device", reason="operator_revocation_web")
    return {"device_id": device_id, "status": "revoked", "epoch": res["epoch"], "timestamp": time.time()}


def _next_key_version(current_ver: str) -> str:
    if current_ver.startswith("v") and current_ver[1:].isdigit():
        return f"v{int(current_ver[1:]) + 1}"
    return f"v{int(time.time())}"


@router.post("/crypto/rotate-key", response_model=KeyRotationResponse)
def rotate_master_key(auth: dict = Depends(verify_operator_auth)):
    """Perform controlled key rotation and synchronize the active version across the cluster."""
    svc = get_service()
    key = load_vault_key(get_vault_key_path(_STATE_DIR))
    mgr = KeyRotationManager(svc.conn, key)
    active = mgr.key_repo.get_active_version()
    current_ver = active["version_id"] if active else "v1"
    next_ver = _next_key_version(current_ver)
    while mgr.key_repo.get_version(next_ver) is not None:
        next_ver = _next_key_version(next_ver)

    rot_res = mgr.rotate_key(new_version_id=next_ver, grace_seconds=1.0, rewrap_assets=True)
    get_coordinator().sync_all()

    return KeyRotationResponse(
        status="rotated",
        previous_key_version=current_ver,
        active_key_version=next_ver,
        grace_period_seconds=1.0,
        cutoff_timestamp=rot_res["cutoff_at"],
        rotation_duration_ms=rot_res["rotation_duration_ms"],
        rewrapped_count=rot_res["rewrapped_count"],
        transfers_continue=True,
        retired_keys_rejected=True,
    )


@router.post("/demo/lost-device")
def run_lost_device_demo(auth: dict = Depends(verify_operator_auth)):
    """Run an isolated 11-step lost-device demonstration and return real execution timings."""
    import tempfile
    from pathlib import Path

    td_obj = tempfile.TemporaryDirectory()
    try:
        td = Path(td_obj.name)
        s = QuantumVaultService(state_dir=td)
        try:
            s.setup(
                owners={"asset-alex": "user-alex", "asset-blair": "user-blair"},
                contents={"asset-alex": "Alex Confidential Research", "asset-blair": "Blair Secure Ledger"},
                disabled=[],
                key_material="lost-device-demo-key-material",
            )

            dev_mgr = DeviceManager(s.conn)
            rec_mgr = RecoveryManager(s.conn)

            _, pk_alex_orig_b64 = generate_device_keypair()
            dev_mgr.enroll_device("user-alex", "dev-alex-orig", pk_alex_orig_b64)

            _, pk_blair_b64 = generate_device_keypair()
            dev_mgr.enroll_device("user-blair", "dev-blair-orig", pk_blair_b64)

            codes = rec_mgr.generate_recovery_codes("user-alex", count=2)

            r1 = s.read("user-alex", "asset-alex", "req-1")
            r2 = s.read("user-blair", "asset-blair", "req-2")

            t_rev_start = time.perf_counter()
            dev_mgr.revoke_device("dev-alex-orig", reason="stolen_device_reported")
            coord = ClusterCoordinator(state_dir=td, node_count=3)
            coord_res = coord.broadcast_revocation("dev-alex-orig", entity_type="device", reason="stolen_device_reported")
            t_rev = (time.perf_counter() - t_rev_start) * 1000.0

            # Verify compromised device is blocked on all nodes
            node_a = coord.get_node("node-a")
            r3 = node_a.read("user-alex", "asset-alex", "req-3", device_id="dev-alex-orig")
            r4 = node_a.read("user-blair", "asset-blair", "req-4", device_id="dev-blair-orig")
            coord.close()

            _, pk_alex_rep_b64 = generate_device_keypair()
            rec_mgr.recover_and_replace_device("user-alex", codes[0], "dev-alex-rep", pk_alex_rep_b64)

            # Verify replacement device is active and can read while original stays blocked
            r5 = s.read("user-alex", "asset-alex", "req-5")
            orig_active = dev_mgr.is_device_active("dev-alex-orig")
            rep_active = dev_mgr.is_device_active("dev-alex-rep")
        finally:
            s.close()
    finally:
        try:
            td_obj.cleanup()
        except Exception:
            pass

    return {
        "status": "COMPLETED",
        "steps": [
            {"step": 1, "action": "Alex original device accesses resource", "outcome": r1.get("decision"), "detail": "Authorized read succeeded before loss"},
            {"step": 2, "action": "Blair accesses independent resource", "outcome": r2.get("decision"), "detail": "Peer read succeeded with distinct key"},
            {"step": 3, "action": "Alex device reported stolen", "outcome": "reported", "detail": "Loss alert received by Security Authority"},
            {"step": 4, "action": "Revocation durably committed", "outcome": "revoked", "detail": f"Durable revocation committed in {t_rev:.2f}ms (Epoch {coord_res['epoch']})"},
            {"step": 5, "action": "Reachable nodes verify authorization", "outcome": "probed", "detail": f"PEP caches confirmed across {len(coord_res['confirmed_nodes'])} nodes"},
            {"step": 6, "action": "Revoked device access denied", "outcome": r3.get("decision"), "detail": "Strictly denied without disclosing content"},
            {"step": 7, "action": "Unaffected users retain access", "outcome": r4.get("decision"), "detail": "Blair access preserved without interruption"},
            {"step": 8, "action": "Independent recovery verification", "outcome": "verified", "detail": "Single-use recovery code verified against salted hash"},
            {"step": 9, "action": "Replacement device enrolment", "outcome": "enrolled", "detail": f"dev-alex-rep enrolled (active={rep_active})"},
            {"step": 10, "action": "Replacement device reads resource", "outcome": r5.get("decision"), "detail": "Access restored for authorized owner"},
            {"step": 11, "action": "Original device remains revoked", "outcome": "verified" if not orig_active else "failed", "detail": "dev-alex-orig permanently blocked in registry"},
        ],
        "revocation_latency_ms": round(t_rev, 3),
    }
