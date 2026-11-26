# QuantumVault — API & Adapter Contract Specification
**Hackathon:** Yugaantar DevForge | **Track:** Track 4: "Trust, but verify"  
**Document Status:** Approved Architectural Planning (Phase-U)

---

## 1. Dual-Interface Architecture

QuantumVault exposes two fully unified interface surfaces:
1. **The Headless Judging Adapter (`track4_service.py`):** The official competition entrypoint at the repository root, driven strictly by standard I/O for automated evaluation.
2. **The Operator & Testing Web API (`api/`):** A lightweight FastAPI server exposing REST endpoints for the live user vault, operator console, and security testing laboratory.

Both interfaces invoke the **exact same underlying dispatcher function** in `quantumvault.core.dispatcher`. There are zero separate code paths or backdoor shortcuts.

---

## 2. Official Adapter Contract v1 Specification

### 2.1 Execution Model
- **Command:** `python -B track4_service.py` (or `python track4_service.py`).
- **Lifecycle:** A new operating system process is spawned for **every operation**. State does not persist in RAM across invocations.
- **Current Working Directory:** Set to the root of the team repository.
- **Input:** Reads one complete UTF-8 JSON object from standard input until EOF.
- **Output:** Writes exactly one JSON object followed by `\n` to standard output; exits with status 0.
- **Diagnostics:** Stderr only. No keys, secrets, or protected file bodies may be emitted to stderr.
- **Buffer Safety:** Stdout and stderr must not exceed 64 KiB (65,536 bytes).

### 2.2 Complete Operation Schemas

#### Operation 1: `setup`
Initializes or resets the application state.
- **Request:**
  ```json
  {
    "op": "setup",
    "owners": {
      "asset-001": "user-alex",
      "asset-002": "user-blair"
    },
    "contents": {
      "asset-001": "Confidential financial report content",
      "asset-002": "Engineering architectural blueprint"
    },
    "disabled": [
      "user-casey"
    ],
    "key_material": "7b3f9a2e8c1d5b0a4f6e8d2c0b4a6e8f"
  }
  ```
- **Required Response:**
  ```json
  {
    "ready": true
  }
  ```
- **Rules:**
  * Must wipe pre-existing state in `TRACK4_STATE_DIR`.
  * Persist the initial owners, contents, and disabled actors.
  * Store or digest `key_material` securely; never echo to stdout or stderr.

#### Operation 2: `read`
Fetches an asset body for an authorized owner.
- **Request:**
  ```json
  {
    "op": "read",
    "actor": "user-alex",
    "asset": "asset-001",
    "request_id": "req-98721"
  }
  ```
- **Authorized Response:**
  ```json
  {
    "decision": "allow",
    "body": "Confidential financial report content"
  }
  ```
- **Denied Response:**
  ```json
  {
    "decision": "deny"
  }
  ```
- **Rules:**
  * If denied (wrong owner, unknown asset, or disabled actor), `decision` must be `"deny"`.
  * The response MUST NOT contain a `body` key or any substring of the protected body.
  * Must record the `request_id` and final `decision` immutably for subsequent auditing.

#### Operation 3: `revoke`
Revokes an actor's access credentials immediately.
- **Request:**
  ```json
  {
    "op": "revoke",
    "actor": "user-alex"
  }
  ```
- **Required Response:**
  ```json
  {}
  ```
- **Rules:**
  * Actor is added to the disabled registry and persisted to disk.
  * Subsequent read requests for this actor must return `{"decision": "deny"}`.
  * Other actors (e.g. `user-blair`) must retain their full permissions unaffected.

#### Operation 4: `audit`
Queries the recorded outcome of a previous read request.
- **Request:**
  ```json
  {
    "op": "audit",
    "request_id": "req-98721"
  }
  ```
- **Required Response:**
  ```json
  {
    "request_id": "req-98721",
    "decision": "allow"
  }
  ```
- **Rules:**
  * Must return the historical decision as recorded during the original operation.
  * If the actor was subsequently revoked, the audit record for a past allowed read must still report `"allow"`.

#### Operation 5: `protected_read`
Executes authenticated post-quantum key encapsulation and proof generation.
- **Request:**
  ```json
  {
    "op": "protected_read",
    "actor": "user-alex",
    "asset": "asset-001",
    "challenge": "ch-random-nonce-9872",
    "public_key": "<Base64_ML_KEM_768_Public_Key_1184_Bytes>"
  }
  ```
- **Authorized Response:**
  ```json
  {
    "ciphertext": "<Base64_KEM_Ciphertext_1088_Bytes>",
    "proof": "7a8f9b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcd"
  }
  ```
- **Denied Response:**
  ```json
  {
    "decision": "deny"
  }
  ```
- **Rules:**
  * Must enforce ownership and revocation policy before any cryptographic encapsulation.
  * Encapsulates using `pqcrypto.kem.ml_kem_768.encaps(pk_bytes)`.
  * Proof is HMAC-SHA-256 over `(challenge + stored_body).encode("utf-8")` keyed by the shared secret.
  * Shared secret must be kept in RAM and erased.

---

## 3. Web REST API Specification

| Method | Endpoint | Description | Request Body | Response Body |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/login` | Authenticate user | `{"username", "password"}` | `{"token", "actor_id", "role"}` |
| `POST` | `/api/vault/upload` | Upload & encrypt asset | `{"asset_id", "body"}` | `{"status": "stored", "asset_id"}` |
| `GET` | `/api/vault/assets` | List owned assets | None (Header Bearer) | `[{"asset_id", "created_at"}]` |
| `POST` | `/api/vault/read` | Read asset (Web UI) | `{"asset_id"}` | `{"decision", "body"}` |
| `POST` | `/api/device/report-lost` | Revoke stolen device | `{"device_id"}` | `{"status": "revoked"}` |
| `POST` | `/api/device/enroll` | Enroll replacement device | `{"device_id", "public_key"}` | `{"status": "enrolled"}` |
| `POST` | `/api/key/rotate` | Trigger key rotation | `{"new_version_id", "grace_sec"}` | `{"status": "rotating", "cutoff_at"}` |
| `GET` | `/api/cluster/nodes` | Get node sync status | None | `[{"node_id", "status", "epoch"}]` |
| `POST` | `/api/backup/create` | Trigger authenticated backup | None | `{"backup_id", "digest", "status"}` |
| `POST` | `/api/backup/restore` | Restore backup snapshot | `{"backup_id"}` | `{"status": "restored", "epoch"}` |
| `GET` | `/api/audit/logs` | Query audit trail | `?limit=50&offset=0` | `{"logs": [...], "hash_valid": true}` |
| `POST` | `/api/threats/analyze` | Ingest and evaluate logs | `{"events_csv", "approvals_json"}` | `{"alerts": [...], "f1_score": 1.0}` |
| `POST` | `/api/testing/run-test` | Execute security lab test | `{"test_id": "test_lost_device"}` | `{"test_id", "passed": true, "details": "..."}` |
| `POST` | `/api/adapter/dispatch` | Direct adapter pass-through | `<Any Adapter JSON Request>` | `<Exact Adapter JSON Response>` |
