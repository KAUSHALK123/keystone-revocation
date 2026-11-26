"""Pydantic schemas for QuantumVault Web API."""
from __future__ import annotations
from typing import Any
from pydantic import BaseModel, Field


class StatusResponse(BaseModel):
    app: str = "QUANTUMVAULT"
    subtitle: str = "Zero-Trust Post-Quantum Security Operations Center"
    version: str = "1.0.0"
    operator: str = "sec-admin"
    role: str = "SOC Administrator"
    mode: str = "MOCK CLUSTER / LOCAL SOC"
    cluster_epoch: int = 1
    active_key_version: str = "v1"
    backend_status: str = "operational"
    pqc_algorithms: list[str] = Field(default_factory=lambda: ["ML-KEM-768 (FIPS 203)", "ML-DSA-65 (FIPS 204)"])
    environment_badges: dict[str, str] = Field(default_factory=lambda: {
        "cluster": "Live Mock Cluster",
        "telemetry": "Practice Dataset (22 Events)",
        "lab": "Isolated Security Laboratory",
        "crypto": "Post-Quantum Cryptography"
    })


class ReadRequest(BaseModel):
    actor: str
    asset: str
    request_id: str = "req-web-01"


class ReadResponse(BaseModel):
    decision: str
    body: str | None = None
    request_id: str


class SetupRequest(BaseModel):
    owners: dict[str, str]
    contents: dict[str, str]
    disabled: list[str] = Field(default_factory=list)
    key_material: str = "synthetic-key-material"


class NodeStatus(BaseModel):
    node_id: str
    name: str
    status: str
    healthy: bool
    last_heartbeat_epoch: int
    key_version: str
    role: str = "worker"


class ClusterStatusResponse(BaseModel):
    current_epoch: int
    active_key_version: str
    grace_period_active: bool
    nodes: list[NodeStatus]


class RevokeClusterRequest(BaseModel):
    entity_id: str = "analyst-1"
    entity_type: str = "actor"
    reason: str = "lost_device_reported"


class RevokeClusterResponse(BaseModel):
    epoch: int
    entity_id: str
    revocation_hash: str
    auth_commit_latency_ms: float
    node_latencies_ms: dict[str, float]
    probe_latencies_ms: dict[str, float]
    confirmed_nodes: list[str]
    total_propagation_ms: float


class NodePartitionRequest(BaseModel):
    node_id: str = "node-c"
    action: str = "disconnect"  # "disconnect" or "reconnect"


class DeviceInfo(BaseModel):
    device_id: str
    owner: str
    status: str
    algorithm: str
    enrolled_at: str
    public_key_preview: str


class KeyRotationResponse(BaseModel):
    status: str
    previous_key_version: str
    active_key_version: str
    grace_period_seconds: float
    cutoff_timestamp: str
    transfers_continue: bool
    retired_keys_rejected: bool


class IntegrityStatusResponse(BaseModel):
    audit_chain_verified: bool
    total_audit_events: int
    tamper_detected: bool
    external_checkpoint_valid: bool
    last_checkpoint_epoch: int
    backup_verified: bool
    last_backup_digest: str


class PracticeEventModel(BaseModel):
    event_id: str
    event_time_utc: str
    received_time_utc: str
    source_clock_offset_ms: int
    corrected_time_utc: str
    actor: str
    source_service: str
    target_service: str
    action: str
    role_before: str
    role_after: str
    outcome: str
    approval_id: str | None
    session_id: str
    correlation_id: str
    predicted_label: str
    ground_truth_label: str
    reason: str
    timing_uncertainty_ms: float


class ThreatOverviewResponse(BaseModel):
    events_processed: int
    routine_events: int
    suspicious_events: int
    active_incidents: int
    unexpected_role_changes: int
    lateral_movement_candidates: int
    approved_changes: int
    delayed_events: int
    clock_offset_events: int


class IncidentModel(BaseModel):
    incident_id: str
    rule_id: str
    incident_type: str
    actor_id: str
    severity: str
    explanation: str
    evidence_event_ids: list[str]
    created_at: str
    recommended_action: str


class ServiceGraphNode(BaseModel):
    id: str
    label: str
    tier: str = "service"


class ServiceGraphEdge(BaseModel):
    source: str
    target: str
    status: str  # "normal", "suspicious_attempted", "denied"
    evidence_events: list[str] = Field(default_factory=list)


class ServiceGraphResponse(BaseModel):
    nodes: list[ServiceGraphNode]
    edges: list[ServiceGraphEdge]


class DetectionMetricsResponse(BaseModel):
    dataset_name: str
    total_events: int
    exact_accuracy: float
    precision: float
    recall: float
    f1_score: float
    false_alerts_per_1000_benign: float
    median_alert_latency_us: float
    throughput_events_per_sec: float
    confusion_matrix: dict[str, int]


class MessagingHandshakeRequest(BaseModel):
    initiator: str = "alice"
    responder: str = "bob"


class MessagingHandshakeResponse(BaseModel):
    session_id: str
    initiator: str
    responder: str
    ephemeral_kem_pk_preview: str
    ciphertext_preview: str
    session_key_derived: bool
    ephemeral_keys_zeroized: bool
    handshake_duration_ms: float
    stages: list[dict[str, Any]]


class MessageSendRequest(BaseModel):
    session_id: str | None = None
    sender: str = "alice"
    recipient: str = "bob"
    plaintext: str = "Top Secret Flight Telemetry Data"


class MessageSendResponse(BaseModel):
    message_id: str
    session_id: str
    sender: str
    recipient: str
    ciphertext_preview: str
    sequence_number: int
    delivered: bool
    verified_recipient: bool
    plaintext_revealed_to_recipient: str


class LabScenarioSummary(BaseModel):
    name: str
    category: str
    description: str


class LabRunResult(BaseModel):
    name: str
    passed: bool
    duration_ms: float
    detail: str = ""


class CombinedScenarioStepResult(BaseModel):
    step: int
    title: str
    status: str
    details: dict[str, Any] = Field(default_factory=dict)


class CombinedScenarioResponse(BaseModel):
    success: bool
    steps_passed: int
    total_steps: int
    execution_time_ms: float
    steps: list[CombinedScenarioStepResult]
