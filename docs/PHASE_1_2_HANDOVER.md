# QuantumVault — Phase 1.2 Integration & Handover Guide

**Project:** QuantumVault  
**From:** Phase 1.1 (Core Security Backend & Judging Adapter)  
**To:** Phase 1.2 (Distributed Security, Device Management & Resilient Persistence)  
**Status:** Approved Handover Specification

---

## 1. Stable Interfaces to Reuse

Phase 1.2 developers must build upon the following verified interfaces without rewriting the core engine:

### 1.1 Database Connection & Transaction Layer (`quantumvault.storage.db`)
- `get_connection(db_path=None)`: Returns an SQLite connection configured with foreign keys, busy timeout, and WAL mode.
- `transaction(conn)`: Atomic transaction context manager (`BEGIN IMMEDIATE` / `COMMIT` / `ROLLBACK`).
- `reset_state(conn)`: Cleans application tables atomically.

### 1.2 Policy Enforcement Point (`quantumvault.iam.policy`)
- `PolicyEngine.evaluate_access(actor, asset, asset_owner, is_disabled)`: Returns `("allow", rule)` or `("deny", rule)`.

### 1.3 Post-Quantum Cryptographic Engine (`quantumvault.crypto.pqc_kem`)
- `MLKEM768.generate_keypair()`: Produces `(pk, sk)` (1184-byte PK, 2400-byte SK).
- `MLKEM768.encapsulate(pk_bytes)`: Produces `(ciphertext, shared_secret)` (1088-byte CT, 32-byte SS).
- `MLKEM768.decapsulate(sk_bytes, ct_bytes)`: Recovers the 32-byte shared secret.

### 1.4 Authenticated Resource Vault (`quantumvault.vault.resources`)
- `ResourceVault.store_resource(asset_id, owner_id, plaintext_body)`: Encrypts body with AES-256-GCM.
- `ResourceVault.retrieve_resource(asset_id)`: Decrypts body after verifying AAD binding.
- `ResourceVault.get_owner(asset_id)`: Checks asset owner without decrypting ciphertext.

### 1.5 Official Adapter Dispatcher (`quantumvault.core.dispatcher`)
- `dispatch(request: dict) -> dict`: Single entrypoint routing all five contract operations.

---

## 2. Phase 1.2 Architecture Extension Roadmap

Phase 1.2 will extend the core without modifying existing passing behavior:

```
Phase 1.1 Baseline                      Phase 1.2 Additions
─────────────────                      ───────────────────
Identities (Actor level)       ──>     Device Registry (Actor + Device ID)
Single SQLite DB               ──>     Multi-Node Cluster Simulation (Nodes A, B, C)
Immediate Revocation           ──>     Distributed Revocation Propagation & Latency Tracking
Static Vault Master Key        ──>     Key Lifecycle Manager (Active, Grace, Cutoff, Retired)
Single-Process Persistence     ──>     Crash-Safe Interrupted Rotation State Machine
Basic Audit Hash (Entry)       ──>     Merkle / SHA-256 Block Chain with Checkpoints
Database Snapshot              ──>     Authenticated AES-GCM Backup with Anti-Rollback Epoch
```

---

## 3. Step-by-Step Extension Instructions for Phase 1.2

1. **Device Registry (`quantumvault/iam/device.py`):**
   - Bind multiple devices to an identity.
   - Support `revoke_device(device_id)` without disabling the actor account.
   - Enforce device-level rejection on reads while allowing clean replacement device enrollment.
2. **Key Lifecycle Manager (`quantumvault/crypto/key_manager.py`):**
   - Add versioning table `key_versions`.
   - Implement state transitions: `pre_active` $\to$ `active` $\to$ `grace_period` $\to$ `retired`.
   - Implement cutoff timestamp checks.
3. **Multi-Node Cluster Simulator (`quantumvault/distributed/cluster.py`):**
   - Simulate distributed instances for Node A, Node B, and Node C.
   - Implement heartbeat monitoring and the fail-closed partition rule (> 5000ms drift).
4. **Backup Integrity & Anti-Rollback (`quantumvault/backup/backup_manager.py`):**
   - Create encrypted database archive with AES-256-GCM.
   - Store monotonic cluster epoch in header to reject rollback attacks.
5. **Audit Chain Checkpoints (`quantumvault/audit/logger.py`):**
   - Link `prev_hash` to create a verifiable hash chain from Entry 0 to Entry N.
