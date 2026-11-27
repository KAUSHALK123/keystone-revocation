# QuantumVault — Phase 2 Handover Specification

**Target Milestone:** Phase 2 (Web Portal, Operator Dashboard, Interactive Visualizations, and Hackathon Final Submission)  
**Handover From:** Phase 1.3 Backend Engineering Team  
**Status:** BACKEND COMPLETE & VERIFIED — READY FOR FRONTEND EXECUTION

---

## 1. Handover Overview

QuantumVault's security backend, cryptographic engine, distributed clustering, threat detection, and post-quantum messaging subsystems are 100% operational, fully documented, and verified across 156 automated tests.

Phase 2 will implement the user-facing layer:
1. **Interactive Operator Dashboard:** Live visual cluster topology, health monitors, real-time revocation broadcast triggers, and propagation latency graphs.
2. **Explainable Threat Detection Console:** Visual timeline of the 22 practice events, interactive dependency graph of service hops, incident details modal with rule justifications, and live evaluation metrics ($F_1$, Precision, Recall).
3. **Post-Quantum Secure Messaging Client:** PQC session initialization UI (ML-KEM-768 + ML-DSA-65), encrypted messaging interface, offline outbox visual queue, and forward-secrecy compromise simulation demo.
4. **Key Lifecycle & Vault Explorer:** Multi-state key rotation manager (`pre_active` -> `active` -> `grace` -> `retired`), asset rewrapping progress bar, and fail-closed denial inspection.
5. **Audit Log & Tamper Explorer:** Verifiable hash chain explorer ($H_N = \text{SHA-256}(H_{N-1} \parallel E_N)$), checkpoint verification status, and interactive tamper-injection demonstration with instant visual red flags.

---

## 2. API Integration Contract

The backend services can be queried directly via Python programmatic interfaces or wrapped in a lightweight FastAPI/Flask HTTP gateway during Phase 2.

### 2.1 Core API Endpoints
- `POST /api/v1/setup`: Initialize clean state with asset owners, encrypted content, disabled actors, and master key material.
- `POST /api/v1/read`: Retrieve asset body with automatic authorization and immutable hash-chained audit logging.
- `POST /api/v1/revoke`: Authoritative actor credential revocation.
- `POST /api/v1/protected-read`: Post-quantum KEM encapsulation against public keys.
- `GET /api/v1/audit/{request_id}`: Query immutable audit record by request ID.

### 2.2 Distributed Cluster & Latency APIs
- `GET /api/v1/cluster/status`: Query active epoch, node health, and cached revocations across Node A, Node B, and Node C.
- `POST /api/v1/cluster/revoke`: Broadcast authoritative revocation and receive separated latency metrics (`auth_commit_latency_ms`, `node_latencies_ms`, `probe_latencies_ms`).
- `POST /api/v1/cluster/partition`: Simulate network partition on a specific node.
- `POST /api/v1/cluster/reconnect`: Restore network connectivity and trigger state synchronization.

### 2.3 Threat Detection APIs
- `GET /api/v1/detection/practice-events`: Retrieve the 22 practice events with true labels and predicted classifications.
- `POST /api/v1/detection/ingest`: Ingest custom or synthetic telemetry streams.
- `GET /api/v1/detection/incidents`: Retrieve open incidents with rule IDs, severity, and evidence event IDs.
- `GET /api/v1/detection/metrics`: Retrieve live confusion matrix, $F_1$, Precision, Recall, and median alert latency.
- `GET /api/v1/detection/graph`: Retrieve directed service communication topology.

### 2.4 Secure Messaging APIs
- `POST /api/v1/messaging/offer`: Bob generates ephemeral ML-KEM-768 keypair and signed offer.
- `POST /api/v1/messaging/initiate`: Alice encapsulates shared secret and signs handshake context.
- `POST /api/v1/messaging/complete`: Bob decapsulates shared secret, zeroizes ephemeral key, and derives symmetric keys.
- `POST /api/v1/messaging/send`: Encrypt message payload under AES-256-GCM with recipient context AAD.
- `POST /api/v1/messaging/receive`: Decrypt message and update sliding window replay protector.
- `POST /api/v1/messaging/simulate-compromise`: Run forward secrecy verification harness and view proof.

---

## 3. Technology Stack Recommendations for Phase 2

- **Frontend Framework:** React 18 / Vite with TypeScript.
- **Styling & UI Components:** Tailwind CSS + Radix UI / Lucide React icons.
- **Visual Graph & Topologies:** React Flow / Vis.js for interactive service graphs and cluster nodes.
- **Charts & Metrics:** Recharts / Chart.js for real-time propagation latency and confusion matrix rendering.
- **Backend Bridge:** FastAPI running on `Uvicorn` with Pydantic v2 schemas wrapping `QuantumVaultService`, `ClusterCoordinator`, `DetectionEngine`, and `MessagingHandshake`.

---

## 4. Key Artifacts for Final Hackathon Submission

1. **Two-Page Brief (`templates/two-page-brief.md`):** Complete USP, architectural diagram, five-minute video link, and one-page threat model.
2. **Evidence Sheet (`evidence-sheet.md`):** All 12 goals marked `measured` with linked benchmark logs and reproduction commands.
3. **Standalone Judging Adapter (`track4_service.py`):** Verified passing all 12 checks of official `validate.py`.
4. **Security Laboratory CLI (`quantumvault.testing.lab`):** Executable with 40 built-in adversarial scenarios.
