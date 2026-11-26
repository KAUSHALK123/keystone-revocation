# QuantumVault — Phase-B Implementation Roadmap
**Hackathon:** Yugaantar DevForge | **Track:** Track 4: "Trust, but verify"  
**Document Status:** Approved Architectural Planning (Phase-U)

---

## 1. Roadmap Architecture & Execution Philosophy

The Phase-B implementation roadmap is engineered around an **uncompromising priority hierarchy**:
1. **P0 (Critical Judging Baseline):** Headless adapter conformance and post-quantum cryptographic correctness.
2. **P1 (Core Security Controls):** Key rotation, multi-node revocation, crash safety, and tamper-evident logging.
3. **P2 (Explainable Threat Detection):** Telemetry clock correction, approval correlation, and service-graph analysis.
4. **P3 (Communication & Resilient Transport):** E2EE messaging, replay protection, and chunked reassembly.
5. **P4 (Interactive Polish & Lab):** Operator dashboard, testing laboratory, and evidence sheet generation.

A core tenet of this roadmap is that **P0 and P1 must be completely verified and locked in before frontend work begins**.

---

## 2. Ordered Milestones for Phase-B

```mermaid
gantt
    title QuantumVault Phase-B Implementation Roadmap
    dateFormat  X
    axisFormat  Day %d
    
    section Foundation & Conformance
    Milestone 1: Judging Adapter & SQLite WAL         :active, M1, 0, 1
    Milestone 2: ML-KEM-768 & HMAC Proofs           :M2, after M1, 1
    
    section Distributed Security
    Milestone 3: Key Lifecycle & Node Sync          :M3, after M2, 1
    Milestone 4: Crash Safety & Backup Integrity    :M4, after M3, 1
    
    section Threat Telemetry
    Milestone 5: Telemetry Detection Engine         :M5, after M4, 1
    
    section Messaging & Transport
    Milestone 6: E2EE Messaging & Replay Defenses   :M6, after M5, 1
    
    section Polish & Deliverables
    Milestone 7: Security Lab & Combined Demo       :M7, after M6, 1
    Milestone 8: Operator & User Frontend Portal    :M8, after M7, 1
    Milestone 9: Final Packaging & Evidence Sheet   :M9, after M8, 1
```

---

### Milestone 1: Minimal Working Judging-Compatible Backend (MVP)
- **Goal:** Pass all 12 checks of the official `validate.py` test harness with exit code 0.
- **Tasks:**
  1. Implement `quantumvault/storage/db.py` (SQLite WAL schema, connection pooling, directory resolver).
  2. Implement `quantumvault/iam/policy.py` (PEP/PDP logic: `owners`, `disabled` check, zero-knowledge deny).
  3. Implement `quantumvault/core/dispatcher.py` (Handling `setup`, `read`, `revoke`, `audit`).
  4. Create root entrypoint `track4_service.py` (JSON streaming, error masking, stream buffer capping).
  5. Create root `threat-model.json` (`{"asset":"protected-resource","boundary":"identity-check"}`).
- **Acceptance Criteria:**
  - Running `python validate.py --entry track4_service.py` outputs 12 `PASS` lines and exits with status 0.
  - Running `python -m unittest tests/test_validate.py` reports `Ran 7 tests ... OK`.

---

### Milestone 2: Post-Quantum Cryptographic Engine (`protected_read`)
- **Goal:** Implement standard ML-KEM-768 key encapsulation and HMAC-SHA-256 proofs.
- **Tasks:**
  1. Implement `quantumvault/crypto/pqc_kem.py` wrapping `pqcrypto.kem.ml_kem_768`.
  2. Implement `quantumvault/crypto/hmac_proof.py` calculating lowercase hex HMAC-SHA-256 over `challenge + stored_body`.
  3. Wire `protected_read` operation into `core/dispatcher.py`.
  4. Implement memory zeroization for in-memory shared secret buffers.
- **Acceptance Criteria:**
  - Standalone verification client successfully encapsulates against a raw 1184-byte Base64 public key and decapsulates to verify matching shared secret and HMAC proof.

---

### Milestone 3: Key Lifecycle & Multi-Node Revocation Simulation
- **Goal:** Demonstrate Objectives 1 and 2 (Key rotation cutoffs and multi-node revocation propagation).
- **Tasks:**
  1. Implement `quantumvault/crypto/key_manager.py` managing 4-state key versions (`pre_active`, `active`, `grace_period`, `retired`).
  2. Implement `quantumvault/distributed/cluster.py` simulating Nodes A, B, and C with monotonic version epochs.
  3. Implement fail-closed restriction logic for partitioned nodes.
  4. Implement clean device re-enrollment workflow in `quantumvault/iam/device.py`.
- **Acceptance Criteria:**
  - Automated tests prove that active transfers finish during grace window, old keys are rejected after cutoff, and revoked devices are barred across all nodes in $\le 25\text{ ms}$.

---

### Milestone 4: Resilient Persistence, Backup Integrity & Tamper-Evident Logging
- **Goal:** Demonstrate Objectives 3, 4, and 5 (Crash safety, backup verification, and audit hash chains).
- **Tasks:**
  1. Implement `quantumvault/audit/logger.py` with SHA-256 hash chaining and control character sanitization.
  2. Implement `quantumvault/backup/backup_manager.py` with AES-256-GCM encryption, HMAC digests, and anti-rollback epoch counters.
  3. Implement atomic file swaps (`.tmp` $\to$ `.db`) for crash-safe recovery.
- **Acceptance Criteria:**
  - Corrupted backup bit-flip test fails restore; stale epoch backup is rejected; hash chain tamper test flags modified row.

---

### Milestone 5: Telemetry Anomaly Detection & Service Graph Engine
- **Goal:** Demonstrate Objectives 6, 7, and 8 (Routine vs suspicious, lateral movement, clock drift).
- **Tasks:**
  1. Implement `quantumvault/detection/clock.py` calculating `corrected_time = event_time - offset`.
  2. Implement `quantumvault/detection/engine.py` correlating `approvals.json` validity.
  3. Implement `quantumvault/detection/service_graph.py` tracking directed graph edge traversals.
- **Acceptance Criteria:**
  - Ingesting `practice/events.csv` outputs Precision = 1.0, Recall = 1.0, F1 = 1.0, MTTA < 5ms, and flags `flow-005` as lateral movement candidate.

---

### Milestone 6: Secure Communication & Transport Protocol
- **Goal:** Demonstrate Objectives 9, 10, and 11 (Replay protection, recipient binding, forward secrecy, lossy transport).
- **Tasks:**
  1. Implement `quantumvault/messaging/e2ee.py` with ephemeral ML-KEM sessions and AEAD envelopes binding recipient public key fingerprints.
  2. Implement sequence-number replay caches.
  3. Implement chunked framing and reassembly in `quantumvault/messaging/transport.py`.
- **Acceptance Criteria:**
  - Replayed messages rejected; tampered recipient fails GCM tag; reordered chunks reassemble bit-for-bit.

---

### Milestone 7: Testing Laboratory & Combined Grand Demo
- **Goal:** Unified test runner executing all 22 test scenarios and the combined failure stress test.
- **Tasks:**
  1. Implement `quantumvault/testing/lab.py` orchestrating automated tests.
  2. Build the 11-step combined grand failure scenario script.
- **Acceptance Criteria:**
  - Running `python -m quantumvault.testing.lab --run-all` executes all 22 tests and outputs formatted telemetry proofs.

---

### Milestone 8: Professional Frontend & Interactive Control Plane
- **Goal:** Deliver an intuitive dark-themed enterprise cybersecurity UI for judges.
- **Tasks:**
  1. Scaffold React + Vite + Tailwind app in `ui/`.
  2. Build Operator Dashboard (Overview, Key Lifecycle, Service Graph Canvas, Audit Verifier).
  3. Build User Vault & E2EE Messaging views.
  4. Build Interactive Testing Lab UI with live terminal logs.
  5. Build production bundle into `ui/dist/`.
- **Acceptance Criteria:**
  - Pre-built static bundle loads cleanly in offline browser, communicating with FastAPI backend.

---

### Milestone 9: Final Submission Packaging & Evidence Sheet
- **Goal:** Finalize submission deliverables matching all competition rules.
- **Tasks:**
  1. Update `templates/evidence-sheet.md` with measured empirical results (`measured`, `partial`).
  2. Generate the **Two-Page Project Brief PDF** (Page 1: USP/Architecture/Video URL; Page 2: Threat Model).
  3. Verify repository cleanliness: zero credentials, zero build trash, single clean adapter at root.
- **Acceptance Criteria:**
  - Clean clone on clean machine passes setup and validation with zero manual fixes.

---

## 3. Scope Management & Deferred Features

If hackathon development time becomes constrained, features will be gracefully dropped in the following order:
1. **Deferred Item 1:** Web-based E2EE real-time chat UI (falls back to CLI/API messaging demonstration).
2. **Deferred Item 2:** Interactive React Flow canvas drag-and-drop editing (falls back to clean SVG graph renderer).
3. **Deferred Item 3:** Session Resumption (Objective 12 is explicitly conditional; marked `not supported` if time runs out).
*Non-Negotiable Core:* Milestones 1 through 7 CANNOT be dropped under any circumstance.
