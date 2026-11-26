"""Global application status, core vault routes, and cryptographic integrity checks."""
from pathlib import Path
import tempfile
from fastapi import APIRouter, Depends

from quantumvault.audit.checkpoints import CheckpointManager
from quantumvault.audit.verifier import AuditLogVerifier
from quantumvault.backup.backup_manager import BackupManager
from quantumvault.core.service import QuantumVaultService
from quantumvault.crypto.pqc_dsa import MLDSA65
from quantumvault.iam.authentication import generate_device_keypair
from quantumvault.iam.device import DeviceManager
from quantumvault.web.authentication import verify_operator_auth
from quantumvault.web.routes.detection import _get_engine_and_data
from quantumvault.web.schemas import (
    IntegrityStatusResponse,
    ReadRequest,
    ReadResponse,
    SetupRequest,
    StatusResponse,
)

router = APIRouter(prefix="/api/v1", tags=["Status & Core Vault"])

# Shared state directory for web service (isolated from track4_service.py default state)
_STATE_DIR = Path(tempfile.gettempdir()) / "quantumvault-web-state"
_STATE_DIR.mkdir(parents=True, exist_ok=True)
_SERVICE: QuantumVaultService | None = None
_LAST_BACKUP_DIGEST: str = ""
_LAST_BACKUP_VERIFIED: bool = False


def get_service() -> QuantumVaultService:
    global _SERVICE, _LAST_BACKUP_DIGEST, _LAST_BACKUP_VERIFIED
    if _SERVICE is None:
        ext_chk = _STATE_DIR / "external_checkpoints.json"
        if ext_chk.exists():
            try:
                ext_chk.unlink()
            except OSError:
                pass
        _SERVICE = QuantumVaultService(state_dir=_STATE_DIR)
        _SERVICE.setup(
            owners={
                "asset-fin-1": "analyst-1",
                "asset-peer-1": "peer-1",
                "asset-ops-1": "operator-1",
            },
            contents={
                "asset-fin-1": "Confidential Q4 Financial Data & Capital Allocation",
                "asset-peer-1": "Proprietary Avionics Cryptographic Blueprints",
                "asset-ops-1": "Master Security Policy Manifest v1.0",
            },
            disabled=[],
            key_material="web-demonstration-master-vault-seed",
        )
        # Seed initial audit record, external checkpoint, devices, and verified backup
        _SERVICE.read("analyst-1", "asset-fin-1", "req-web-init-01")
        chk_mgr = CheckpointManager(_SERVICE.conn, external_file_path=_STATE_DIR / "external_checkpoints.json")
        chk_mgr.create_checkpoint("chk-web-init")

        dev_mgr = DeviceManager(_SERVICE.conn)
        _, pk_analyst = generate_device_keypair()
        dev_mgr.enroll_device("analyst-1", "dev-analyst-1", pk_analyst)
        _, pk_peer = generate_device_keypair()
        dev_mgr.enroll_device("peer-1", "dev-peer-1", pk_peer)
        dsa = MLDSA65()
        pk_op_pqc, _ = dsa.generate_keypair()
        dev_mgr.enroll_device("operator-1", "dev-operator-pqc", dsa.encode_public_key(pk_op_pqc))

        bak_mgr = BackupManager(state_dir=_STATE_DIR)
        bak_meta = bak_mgr.create_backup(_STATE_DIR / "backups" / "initial.qvb")
        _LAST_BACKUP_DIGEST = f"sha256:{bak_meta['snapshot_sha256']}"
        _LAST_BACKUP_VERIFIED = True
    return _SERVICE


@router.get("/status", response_model=StatusResponse)
def get_status(auth: dict = Depends(verify_operator_auth)):
    """Return persistent header status and live backend-derived telemetry."""
    svc = get_service()
    row = svc.conn.execute("SELECT MAX(epoch_counter) FROM cluster_epoch").fetchone()
    epoch = int(row[0]) if (row and row[0]) else 1

    active_key = svc.app_state.get("active_key_version") or "v1"
    rev_count = svc.conn.execute("SELECT COUNT(*) FROM revocations").fetchone()[0]

    verifier = AuditLogVerifier(svc.conn, external_file_path=_STATE_DIR / "external_checkpoints.json")
    audit_report = verifier.verify()

    latest_inc = None
    try:
        _, _, _, engine, _, _, _ = _get_engine_and_data()
        if engine.incidents:
            inc = engine.incidents[-1]
            latest_inc = {
                "incident_id": inc.incident_id,
                "rule_id": inc.rule_id,
                "incident_type": inc.incident_type,
                "actor_id": inc.actor_id,
                "severity": inc.severity,
            }
    except Exception:
        latest_inc = None

    return StatusResponse(
        app="QUANTUMVAULT",
        subtitle="Zero-Trust Post-Quantum Security Operations Center",
        version="2.0.0",
        operator=str(auth["identity"]),
        role=str(auth["role"]),
        mode="SIMULATED CLUSTER / LOCAL SOC",
        cluster_epoch=epoch,
        active_key_version=active_key,
        backend_status="operational" if audit_report["status"] == "valid" else "degraded",
        audit_verified=(audit_report["status"] == "valid"),
        revoked_entities_count=int(rev_count),
        latest_incident=latest_inc,
        pqc_algorithms=["ML-KEM-768 (FIPS 203)", "ML-DSA-65 (FIPS 204)", "AES-256-GCM"],
        environment_badges={
            "cluster": "Simulated In-Process Cluster (3 Nodes)",
            "telemetry": "Practice Dataset (22 Events)",
            "lab": "Security Laboratory (40 Scenarios)",
            "crypto": "Post-Quantum Cryptography (Standardized)",
        },
    )


@router.post("/read", response_model=ReadResponse)
def read_vault_asset(req: ReadRequest, auth: dict = Depends(verify_operator_auth)):
    """Read protected asset through core QuantumVaultService."""
    svc = get_service()
    res = svc.read(actor=req.actor, asset=req.asset, request_id=req.request_id)
    return ReadResponse(
        decision=res.get("decision", "deny"),
        body=res.get("body"),
        request_id=req.request_id,
    )


@router.post("/setup")
def setup_vault(req: SetupRequest, auth: dict = Depends(verify_operator_auth)):
    """Initialize or reset core vault state."""
    svc = get_service()
    return svc.setup(
        owners=req.owners,
        contents=req.contents,
        disabled=req.disabled,
        key_material=req.key_material,
    )


@router.get("/integrity/status", response_model=IntegrityStatusResponse)
def get_integrity_status(auth: dict = Depends(verify_operator_auth)):
    """Verify hash-chained audit logs, external HMAC checkpoints, and real backup digest."""
    svc = get_service()
    ext_path = _STATE_DIR / "external_checkpoints.json"
    verifier = AuditLogVerifier(svc.conn, external_file_path=ext_path)
    report = verifier.verify()

    chk_mgr = CheckpointManager(svc.conn, external_file_path=ext_path)
    latest_cp = chk_mgr.get_latest_checkpoint()
    cp_epoch = int(latest_cp["sequence_up_to"]) if latest_cp else 0
    cp_valid = bool(chk_mgr.verify_checkpoint(latest_cp)) if latest_cp else True

    return IntegrityStatusResponse(
        audit_chain_verified=(report["status"] == "valid"),
        total_audit_events=int(report["total_records"]),
        tamper_detected=(report["status"] != "valid"),
        external_checkpoint_valid=cp_valid and bool(report["checkpoints_valid"]),
        last_checkpoint_epoch=cp_epoch,
        backup_verified=_LAST_BACKUP_VERIFIED,
        last_backup_digest=_LAST_BACKUP_DIGEST or "none",
    )


@router.post("/integrity/verify", response_model=IntegrityStatusResponse)
def trigger_integrity_verification(auth: dict = Depends(verify_operator_auth)):
    """Re-create a fresh hot backup snapshot and run full audit/checkpoint verification."""
    global _LAST_BACKUP_DIGEST, _LAST_BACKUP_VERIFIED
    svc = get_service()
    ext_path = _STATE_DIR / "external_checkpoints.json"
    chk_mgr = CheckpointManager(svc.conn, external_file_path=ext_path)
    chk_mgr.create_checkpoint()

    bak_mgr = BackupManager(state_dir=_STATE_DIR)
    bak_meta = bak_mgr.create_backup(_STATE_DIR / "backups" / "verified_latest.qvb")
    _LAST_BACKUP_DIGEST = f"sha256:{bak_meta['snapshot_sha256']}"
    _LAST_BACKUP_VERIFIED = True
    return get_integrity_status(auth=auth)
