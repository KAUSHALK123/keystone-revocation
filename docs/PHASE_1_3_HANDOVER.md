# QuantumVault — Phase 1.3 Integration & Handover Guide

**Project:** QuantumVault  
**From:** Phase 1.2 (Distributed Security, Key Rotation, Device Recovery & Resilient Persistence)  
**To:** Phase 1.3 (Threat Detection, Secure Messaging Protocols & Backend Security Lab)  
**Status:** Approved Handover Specification  
**Date:** 2026-11-26  

---

## 1. Stable Interfaces to Reuse

Phase 1.3 engineers must build upon the following verified interfaces without modifying their contracts:

### 1.1 Multi-Node Cluster & Authority (`quantumvault.distributed`)
- `ClusterCoordinator(state_dir=None, node_count=3)`: Orchestrates Nodes A, B, C; provides `broadcast_revocation(entity_id, entity_type)` and `sync_all()`.
- `ServiceNode`: Local PEP with `read()`, `protected_read()`, `is_healthy()`, and automatic fail-closed isolation (> 5000 ms partition drift).
- `SecurityAuthority`: Central epoch manager with `get_current_epoch()`, `issue_revocation()`, and `compute_revocation_hash()`.

### 1.2 Device Identity, Authentication & Recovery (`quantumvault.iam`)
- `DeviceManager(conn)`: `enroll_device()`, `revoke_device()`, `is_device_active()`, `list_actor_devices()`.
- `DeviceAuthenticator(conn)`: `create_challenge(device_id)`, `verify_response(device_id, challenge, signature_b64)`.
- `RecoveryManager(conn)`: `generate_recovery_codes(actor_id)`, `verify_and_consume(actor_id, code)`, `recover_and_replace_device()`.
- `PolicyEngine`: `evaluate_access(actor, asset, owner, is_disabled, role, device_id, is_device_revoked)`.

### 1.3 Cryptographic Key Lifecycle Manager (`quantumvault.crypto.rotation`)
- `KeyRotationManager(conn, kek)`:
  - `rotate_key(new_version_id, grace_seconds, rewrap_assets)`: 4-state lifecycle (`pre_active` $\to$ `active` $\to$ `grace_period` $\to$ `retired`).
  - `get_key_for_version(version_id)`: Enforces `cutoff_at` timestamp.
  - `recover_interrupted_rotation()`: Restores durability after unexpected process termination.

### 1.4 Authenticated Backup & Anti-Rollback (`quantumvault.backup`)
- `BackupManager(state_dir)`: `create_backup(target_path)` produces AES-256-GCM + HMAC package bound to cluster epoch.
- `BackupRestoreManager(state_dir)`: `verify_and_restore(backup_path)` enforces anti-rollback check (`backup.epoch >= current.epoch`).

### 1.5 Authenticated Audit Chaining & Verification (`quantumvault.audit`)
- `AuditLogger(conn)`: `log_decision()` links entries via SHA-256 hash chain ($H_N = \text{SHA-256}(H_{N-1} \parallel E_N)$).
- `CheckpointManager(conn)`: `create_checkpoint()` creates HMAC-signed external checkpoints.
- `AuditLogVerifier(conn)`: `verify()` recomputes full chain, returning `status: 'valid' | 'tampered'` with exact error type and sequence.

---

## 2. Phase 1.3 Scope & Objective Roadmap

Phase 1.3 will focus on Objectives 6 through 12, threat telemetry analysis, and secure transport protocols:

```
Phase 1.2 Baseline                          Phase 1.3 Additions
─────────────────                          ───────────────────
Deterministic PEP Decisions         ──>    Explainable Anomaly & Threat Detection (Obj 6)
Isolated Access Events              ──>    Lateral Movement & Session Graph Correlation (Obj 7)
Unsynchronized Timestamps           ──>    Clock Uncertainty Modeling & Timeline Alignment (Obj 8)
Static ML-KEM Key Exchange          ──>    Ephemeral Forward-Secure Messaging & Zeroization (Obj 10)
Immediate Delivery Assumption       ──>    Ordered, Chunked & Loss-Tolerant Delivery (Obj 9, 11)
Single-Shot Operations              ──>    Session Resumption & State Transition Caching (Obj 12)
Independent Subsystem Unit Tests    ──>    Integrated Backend Security Testing Laboratory
```

---

## 3. Step-by-Step Instructions for Phase 1.3 Engineers

### Step 1: Telemetry Ingestion & Practice Dataset Processor (`quantumvault/threat/`)
1. Ingest `practice/events.csv`, `practice/labels.csv`, and `practice/approvals.json` from `references/track4-toolkit/`.
2. Map practice event fields (`event_id`, `actor_id`, `source_ip`, `target_resource`, `edge_node`, `clock_raw`, `uncertainty_ms`).
3. Build a feature extraction pipeline converting raw audit and telemetry streams into structured security observations.

### Step 2: Anomaly Detection & Threat Classification Engine (Objective 6 & 7)
1. Implement heuristic and statistical rule-based classifiers to detect:
   - Routine authorized changes vs. anomalous privilege escalation.
   - Brute-force challenge failures and rapid device hopping.
   - Lateral movement sequences: Correlate events `evt-010`, `evt-011`, `evt-012` by actor, source IP, edge node, and failed attempts.
2. Produce structured explanation objects explaining *why* an activity was flagged (e.g. `rule_id`, `evidence_vector`, `confidence_score`).
3. Benchmark against the official practice set: compute precision, recall, and F1 score without overfitting.

### Step 3: Clock Uncertainty & Timeline Alignment (Objective 8)
1. Model timestamp intervals: $[T - \Delta, T + \Delta]$ where $\Delta$ represents node clock uncertainty.
2. Implement topological / interval sorting to reconstruct canonical event ordering despite multi-node clock drift (e.g. `evt-015`).
3. Preserve original wall-clock timestamps alongside corrected intervals.

### Step 4: Ephemeral Messaging & Forward Secrecy Protocol (Objectives 9, 10, 11)
1. Implement double-ratchet or ephemeral ML-KEM session key derivation for message exchanges.
2. Enforce prompt zeroization of intermediate session keys upon message receipt to guarantee forward secrecy.
3. Implement sequence numbering, sliding window replay caches, and chunked reassembly to survive message loss and reordering (`evt-013`, `evt-014`).

### Step 5: Integrated Backend Security Testing Laboratory (`quantumvault/testing/`)
1. Create a unified CLI/test suite exercising:
   - Practice event evaluations (`test_threat_detection.py`)
   - Lateral movement correlation (`test_lateral_movement.py`)
   - Clock drift timeline reconstruction (`test_clock_uncertainty.py`)
   - Secure protocol forward secrecy and replay defense (`test_secure_protocol.py`)
2. Export comprehensive telemetry metrics to `evidence/phase-1.3/`.
