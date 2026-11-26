# QuantumVault — API Integration Contract

**Document Version:** 1.0 (Phase 1.3 / Phase 2 Interface)  
**Protocol:** REST / JSON over HTTP  
**Default Host / Port:** `http://localhost:8000`

---

## 1. Core Adapter & Vault Endpoints

### 1.1 Setup Initial State
- **Route:** `POST /api/v1/setup`
- **Request Body:**
```json
{
  "owners": {
    "asset-fin-1": "analyst-1",
    "asset-peer-1": "peer-1"
  },
  "contents": {
    "asset-fin-1": "Confidential Q4 Financial Data",
    "asset-peer-1": "Engineering Blueprints"
  },
  "disabled": [],
  "key_material": "master-vault-seed-material"
}
```
- **Response (200 OK):**
```json
{
  "ready": true
}
```

### 1.2 Access Protected Asset
- **Route:** `POST /api/v1/read`
- **Request Body:**
```json
{
  "actor": "analyst-1",
  "asset": "asset-fin-1",
  "request_id": "req-001"
}
```
- **Response Allowed (200 OK):**
```json
{
  "decision": "allow",
  "body": "Confidential Q4 Financial Data"
}
```
- **Response Denied (200 OK):**
```json
{
  "decision": "deny"
}
```

---

## 2. Distributed Cluster Endpoints

### 2.1 Cluster Status & Health
- **Route:** `GET /api/v1/cluster/status`
- **Response (200 OK):**
```json
{
  "current_epoch": 3,
  "active_key_version": "v1",
  "nodes": [
    {
      "node_id": "node-a",
      "status": "online",
      "healthy": true,
      "last_heartbeat_epoch": 3
    },
    {
      "node_id": "node-b",
      "status": "online",
      "healthy": true,
      "last_heartbeat_epoch": 3
    },
    {
      "node_id": "node-c",
      "status": "online",
      "healthy": true,
      "last_heartbeat_epoch": 3
    }
  ]
}
```

### 2.2 Broadcast Revocation Across Cluster
- **Route:** `POST /api/v1/cluster/revoke`
- **Request Body:**
```json
{
  "entity_id": "compromised-user",
  "entity_type": "actor",
  "reason": "lost_device_reported"
}
```
- **Response (200 OK):**
```json
{
  "epoch": 4,
  "entity_id": "compromised-user",
  "revocation_hash": "91a48ae4f838d8dacd3b4ca043f54a71f4c1a6ef78d6f53c5d4c41cf52bdde73",
  "auth_commit_latency_ms": 1.987,
  "node_latencies_ms": {
    "node-a": 0.008,
    "node-b": 0.006,
    "node-c": 0.007
  },
  "probe_latencies_ms": {
    "node-a": 1.895,
    "node-b": 2.061,
    "node-c": 2.448
  },
  "confirmed_nodes": ["node-a", "node-b", "node-c"],
  "total_propagation_ms": 6.480
}
```

---

## 3. Threat Detection Endpoints

### 3.1 Live Practice Telemetry Evaluation
- **Route:** `GET /api/v1/detection/practice-events`
- **Response (200 OK):**
```json
{
  "total_events": 22,
  "exact_accuracy": 1.0,
  "f1_score": 1.0,
  "events": [
    {
      "event_id": "evt-001",
      "event_time_utc": "2026-01-15T09:00:00.000Z",
      "corrected_time_utc": "2026-01-15T09:00:00.000Z",
      "actor": "user-alex",
      "source_service": "portal",
      "target_service": "identity",
      "predicted_label": "routine",
      "ground_truth_label": "routine",
      "reason": "Normal viewer sign-in"
    }
  ]
}
```

### 3.2 Security Incidents
- **Route:** `GET /api/v1/detection/incidents`
- **Response (200 OK):**
```json
[
  {
    "incident_id": "inc-001",
    "rule_id": "RULE-002",
    "incident_type": "unexpected_role_change",
    "actor_id": "user-blair",
    "severity": "high",
    "explanation": "No approved change record exists authorizing user-blair to assume operator",
    "evidence_event_ids": ["evt-008"],
    "created_at": "2026-01-15T09:03:05.200Z"
  },
  {
    "incident_id": "inc-002",
    "rule_id": "RULE-004",
    "incident_type": "lateral_movement_candidate",
    "actor_id": "svc-report-worker",
    "severity": "critical",
    "explanation": "Correlated progression of 3 unauthorized service hops across flow flow-005",
    "evidence_event_ids": ["evt-010", "evt-011", "evt-012"],
    "created_at": "2026-01-15T09:04:00.100Z"
  }
]
```

---

## 4. Post-Quantum Messaging Endpoints

### 4.1 Ephemeral Handshake (ML-KEM-768 + ML-DSA-65)
- **Route:** `POST /api/v1/messaging/handshake/offer`
- **Response (200 OK):**
```json
{
  "session_id": "sess-8b9a14c3e802",
  "responder_id": "bob",
  "responder_device": "dev-bob-mobile",
  "ephemeral_kem_pk_b64": "...",
  "timestamp": "2026-11-26T18:00:00.000Z",
  "signature_b64": "..."
}
```

### 4.2 Forward Secrecy Simulation Proof
- **Route:** `GET /api/v1/messaging/forward-secrecy-proof`
- **Response (200 OK):**
```json
{
  "session_id": "sess-2eb7f21ecbe2ae81d19615315f4aa357",
  "forward_secrecy_preserved": true,
  "ephemeral_key_zeroized": true,
  "adversary_compromised_keys": ["alice_signing_key", "bob_signing_key"],
  "captured_transcript_decrypted": false
}
```
