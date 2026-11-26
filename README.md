# QuantumVault

**A compromise-resilient post-quantum security platform that preserves authorized access during key changes, device loss, network partitions and infrastructure failures, while providing verifiable recovery and explainable detection of suspicious identities.**

**Hackathon:** Yugaantar DevForge | **Track 4:** "Trust, but verify"  
**Version:** 2.0.0 (Phase 2 Security Operations Center, Web Integration & Final Hackathon Deliverables Complete)

---

## 1. Project Overview

QuantumVault is an enterprise-grade security platform designed to protect confidential data assets across dynamic identity and cryptographic transitions. 

In Phase 2, QuantumVault pairs its battle-tested, zero-external-dependency judging backend (`track4_service.py`) with a dedicated, lightweight, 100% offline-compatible **Security Operations Center (SOC) Operator Dashboard** (`quantumvault/web/`) providing visual proof, interactive incident investigation, and automated security verification across all 12 hackathon objectives:

- **Key Rotation (Objective 1):** 4-state lifecycle (`pre_active`, `active`, `grace_period`, `retired`) with cutoff timestamp enforcement, in-flight read preservation, and automatic DEK asset re-wrapping (100 assets re-wrapped in 7.42 ms).
- **Revocation Across Nodes (Objective 2):** 3-node mock cluster (Node A, Node B, Node C) with local Policy Enforcement Point (PEP) caching, centralized Security Authority epoch management, sub-millisecond propagation telemetry (mean: 0.0235 ms), and strict fail-closed isolation on network partitions (> 5000 ms heartbeat threshold).
- **Device Management & Emergency Recovery (Objective 2):** Multi-device challenge-response authentication supporting both classical Ed25519 and native NIST ML-DSA-65 (FIPS 204) post-quantum digital signatures, granular device revocation, and high-entropy salted single-use recovery credentials.
- **Crash Recovery & Anti-Resurrection (Objective 3):** SQLite Write-Ahead Logging (WAL) durability, clean uncommitted transaction rollbacks, crash-safe interrupted key rotation resumption, and cryptographic anti-resurrection of revoked credentials.
- **Backup Integrity & Anti-Rollback Defense (Objective 4):** Consistent online database snapshots encrypted with AES-256-GCM, authenticated with HMAC-SHA-256, and bound to the monotonic cluster epoch. Stale backups restoring older epochs to resurrect revoked keys are strictly detected and rejected (`backup.epoch < current.epoch`).
- **Log Integrity & Audit Verification (Objective 5):** Cryptographic SHA-256 hash chaining ($H_N = \text{SHA-256}(H_{N-1} \parallel E_N)$) from genesis, signed external HMAC checkpoints, and an auditor verification tool capable of verifying 1,000 events in 7.24 ms and detecting any modification, deletion, injection, or history truncation.
- **Explainable Threat Detection (Objectives 6 & 7):** Deterministic, rule-and-graph-based engine (**ZERO AI/ML**) evaluated on official 22 practice events. Achieved **100.0% Exact Classification Accuracy** ($F_1 = 1.000$, Precision = 1.000, Recall = 1.000). Detects approved changes, unapproved role elevations, reviews following role changes, lateral movement candidate sequences (`evt-010..012`), and isolated denials (`evt-020`) with 8,414 events/sec throughput.
- **Clock Uncertainty Normalization (Objective 8):** Normalizes source clock offsets (`evt-015` with +2000 ms to exact UTC reference `09:06:01.000Z`) while preserving raw timestamps and receipt order.
- **Post-Quantum Forward-Secure Messaging (Objectives 9 & 10):** Ephemeral NIST ML-KEM-768 session establishment, identity signatures (ML-DSA-65 / Ed25519), and AES-256-GCM AEAD encryption with recipient AAD binding. Ephemeral private keys are zeroized in RAM immediately after decapsulation. Post-compromise forward secrecy is proven mathematically and programmatically under simulated identity key theft.
- **Replay Protection & Deduplication (Objective 9):** 64/128-entry sliding window bitmask and persistent SQLite deduplication cache rejecting message replays in 3.20 microseconds.
- **Chunked Transport & Encrypted Offline Outbox (Objective 11):** Bounded chunk framing with per-chunk and overall SHA-256 hashes, out-of-order reassembly (59.13 MB/s), loss detection, and an encrypted offline outbox with strict **fail-closed** authorization upon reconnection.
- **Session Resumption Policy (Objective 12):** Explicitly declared and enforced as **NOT SUPPORTED BY POLICY** (`SecurityPolicyError`) to eliminate persistent session ticket, PSK theft, and token reuse attack surfaces; fresh ephemeral ML-KEM-768 handshakes are enforced on every session.
- **Security Operations Center (SOC) Dashboard (Phase 2):** 100% offline-compatible single-page web app (FastAPI backend + Vanilla HTML/CSS/JS) protected by per-process CSPRNG operator token authentication (`X-Operator-Token` / `HttpOnly` SameSite cookie), featuring 5 interactive panels: Cluster Nodes & Revocation, Threat Radar & Incident Graph, Post-Quantum Secure Messaging, Automated Security Laboratory, and a dedicated **15-Step Guided Judge Demo Mode**.
- **Unified Security Testing Laboratory CLI:** `python -m quantumvault.testing.lab` with 40 built-in scenarios covering all subsystems (**40/40 PASSED**).
- **Complete Test Coverage:** Comprehensive **182-test automated suite** covering all core security, cryptography, distributed cluster, hardening regressions, and web API endpoints (**182/182 PASSED**).
- **Official Judging Adapter Conformance:** Root adapter `track4_service.py` satisfies all 12 checks of official `validate.py` harness with exit code 0.

---

## 2. Supported Runtimes & Dependencies

- **Python Runtime:** Python 3.12 (standard judging runtime) or Python 3.11+.
- **Core Dependencies (`requirements-core.txt`):**
  - `pqcrypto==0.4.0` (Native bindings for NIST ML-KEM-768 / FIPS 203 and NIST ML-DSA-65 / FIPS 204)
  - `cryptography>=42.0.0` (AES-256-GCM authenticated cipher & Ed25519 signatures)
- **Web & Operator Dashboard Dependencies (`requirements-web.txt`):**
  - `fastapi>=0.110.0` (Lightweight asynchronous web framework)
  - `uvicorn>=0.28.0` (ASGI production server)
  - `pydantic>=2.6.0` (Data validation and schema serialization)
  - `httpx>=0.27.0` (Test client and HTTP utilities)
- **Zero External Network Invocations:** The judging adapter `track4_service.py` requires zero external network connections or cloud services. The SOC web dashboard is 100% self-contained with no external CDNs, Google Fonts, or remote analytics.
- **Self-Contained Storage:** SQLite 3 WAL persistence with clean atomic transactions.

---

## 3. Quickstart & Adapter Usage

### 3.1 Clone & Environment Setup
```bash
git clone https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit.git references/track4-toolkit
pip install -r requirements-core.txt
pip install -r requirements-web.txt
```

### 3.2 Running the Official Judging Adapter
The root adapter `track4_service.py` reads a single JSON request from `stdin` and writes the JSON response to `stdout`:

```bash
# Setup clean state
echo '{"op":"setup","owners":{"f1":"alice"},"contents":{"f1":"Secret Note"},"disabled":[],"key_material":"marker"}' | python track4_service.py

# Authorized read
echo '{"op":"read","actor":"alice","asset":"f1","request_id":"r01"}' | python track4_service.py
# Output: {"decision": "allow", "body": "Secret Note"}

# Revoke actor
echo '{"op":"revoke","actor":"alice"}' | python track4_service.py
# Output: {}

# Post-revocation read (Zero-Knowledge Deny)
echo '{"op":"read","actor":"alice","asset":"f1","request_id":"r02"}' | python track4_service.py
# Output: {"decision": "deny"}

# Query historical audit decision
echo '{"op":"audit","request_id":"r01"}' | python track4_service.py
# Output: {"request_id": "r01", "decision": "allow"}

# Protected read with post-quantum encapsulation
echo '{"op":"protected_read","actor":"alice","asset":"f1","challenge":"c01","public_key":"<BASE64_KEY>"}' | python track4_service.py
```

### 3.3 Running the Official Toolkit Validator
```bash
python references/track4-toolkit/validate.py --entry track4_service.py
# Local lost-device validator: 12/12 PASS (Exit code 0)
```

---

## 4. Security Operations Center (SOC) Operator Dashboard

To launch the web dashboard for live desk reviews, visual demonstration, and interactive threat inspection:

```bash
python -m quantumvault.web.app
```
Then navigate to **`http://127.0.0.1:8000`** in any modern web browser.

### 4.1 Dashboard Capabilities
1. **Cluster Nodes & Revocation:**
   - Real-time visualization of Authority, Node A, Node B, and Node C.
   - Interactive instant broadcast revocation across all nodes with live latency measurements.
   - Node network partition simulation proving strict **fail-closed** denial during partition.
   - Live 11-step interactive Lost-Device Demonstration showing:
     * Device loss reporting.
     * Instant revocation of the lost hardware token.
     * Ongoing access preservation for unaffected peers.
     * Single-use cryptographic recovery code verification.
     * Enrollment of the replacement device.
     * Permanent rejection of the compromised device.
2. **Threat Radar & Explainable Incident Graph:**
   - 22 practice access events interactive playback (Play / Pause / Step / Reset).
   - Dynamic SVG Service Topology Graph mapping identities to services, highlighting suspicious lateral movement paths (`candidate_lateral_movement_sequence`) in glowing crimson red.
   - 100% deterministic incident breakdown with rule references, empirical metric cards ($F_1 = 1.000$, 0% false positives, 8,414 events/sec throughput).
   - Drill-down modal drawer explaining event actors, roles, justifications, and raw timestamp normalization.
3. **Post-Quantum Secure Messaging:**
   - Ephemeral NIST ML-KEM-768 + ML-DSA-65 handshake visualization.
   - Live interactive messaging between Alice and Bob with recipient-bound AAD.
   - One-click adversarial attack tests:
     * **Replay Attack Test:** Proves duplicate packet rejection via sliding window.
     * **Recipient Tampering Test:** Proves AEAD decryption failure if packet is misdelivered.
     * **Post-Compromise Forward Secrecy Simulation:** Simulates theft of long-term identity keys and verifies past session confidentiality remains intact.
     * **Chunked Transport Simulation:** Injects out-of-order packet arrival and packet loss.
     * **Encrypted Offline Outbox:** Queues messages offline and enforces fail-closed authorization check before retransmission.
4. **Security Testing Laboratory & Evidence Viewer:**
   - One-click runner for all 40 automated test scenarios with real-time pass/fail progress bar.
   - Combined 40-step resilience scenario runner.
   - Path-traversal-guarded audit report and benchmark evidence viewer.

---

## 5. Verification & Testing Suite

### 5.1 Full Automated Test Suite (182 Tests)
Execute the complete 182-test automated test suite covering all modules, hardening edge cases, cryptography, independent threat-detection evaluation, and web API endpoints:
```bash
python -m unittest discover tests -v
```
*Expected Result:* `Ran 182 tests ... OK` (100% PASS, 0 failures, 0 errors).

### 5.2 Unified Security Testing Laboratory CLI (40 Scenarios)
```bash
# List all 40 registered scenarios
python -m quantumvault.testing.lab --list

# Run all 40 scenarios
python -m quantumvault.testing.lab --run-all
# Output: 40/40 scenarios PASSED
```

### 5.3 Combined 40-Step Security Resilience Demonstration
```bash
python -m quantumvault.testing.phase_1_3_combined_scenario
# Output: 40/40 steps PASSED
```

### 5.4 Performance Baselines
Run the comprehensive benchmark suite to regenerate latency percentiles (`median`, `p95`, `p99`, `max`):
```bash
python scripts/benchmark_comprehensive.py
```

| Benchmark Domain | Metric | Measured Median | p95 / Max |
| --- | --- | --- | --- |
| **Adapter Subprocess** | Fresh Process Read (`track4_service.py`) | **332.72 ms** | 360.69 ms / 1281.51 ms |
| **Core Reads (In-Process)** | Authorized / Unauthorized Read | **4.64 ms / 4.47 ms** | 7.64 ms / 6.73 ms (p95) |
| **Key Rotation & Rewrap** | 100 Assets Total Rotation | **15.63 ms** | 18.56 ms / 21.53 ms |
| **3-Node Propagation** | Broadcast + Real Probe Verification | **11.62 ms** | 14.53 ms / 23.29 ms |
| **Backup & Restore** | Hot Backup Creation / Anti-Rollback Restore | **31.97 ms / 13.13 ms** | 119.79 ms / 15.25 ms (p95) |
| **Audit Log Integrity** | 1,000 Events Verification | **9.79 ms** | 10.60 ms / 13.16 ms |
| **Threat Detection Engine** | 22 Practice Events Processing | **0.59 ms** | 0.80 ms / 0.94 ms (**44,417 evt/s**) |
| **PQC Handshake** | ML-KEM-768 + ML-DSA-65 | **4.43 ms** | 6.55 ms / 6.82 ms |
| **AEAD Messaging** | AES-256-GCM Encrypt / Decrypt | **0.011 ms / 0.007 ms** | 0.027 ms / 0.015 ms (p95) |

---

## 6. Hackathon Deliverables & Documentation Index

- **`track4_service.py`:** Root official judging adapter strictly conforming to Adapter Contract v1.
- **`evidence-sheet.md`:** Official 12-objective evidence sheet mapping every requirement to measured evidence.
- **`templates/two-page-brief.md`:** Two-page executive brief, USP analysis, fallback video link placeholder, and 1-page threat model.
- **`docs/DEMO_SCRIPT.md`:** Complete 5-minute video presentation script with minute-by-minute cues, talk tracks, and technical Q&A preparation.
- **`docs/COMPLIANCE_AUDIT.md`:** Comprehensive compliance report verifying adherence to hackathon rules (zero AI/ML, zero hardcoded keys, zero external CDNs, synthetic identities only).
- **`evidence/phase-2/`:** Verifiable execution logs, automated test results, benchmark summaries, and offline audits.

---

## 7. Directory Layout

```
quantumvault/
├── config.py                 # Environment and directory path resolver
├── core/
│   ├── errors.py             # Domain exceptions
│   ├── service.py            # High-assurance core coordinator
│   └── dispatcher.py         # Adapter Contract v1 dispatcher
├── crypto/
│   ├── pqc_kem.py            # NIST ML-KEM-768 encapsulation/decapsulation
│   ├── encryption.py         # Authenticated AES-256-GCM cipher
│   ├── key_manager.py        # HKDF-SHA-256 KEK derivation
│   ├── hmac_proof.py         # Proof generation and ephemeral zeroization
│   └── rotation.py           # 4-state key lifecycle, cutoffs & asset rewrapping
├── distributed/
│   ├── node.py               # Service node with local PEP and fail-closed isolation
│   ├── authority.py          # Security authority managing epochs and revocations
│   └── cluster.py            # 3-node cluster coordinator with latency telemetry
├── iam/
│   ├── identity.py           # Identity dataclass
│   ├── policy.py             # Multi-role and device-aware PDP/PEP engine
│   ├── device.py             # Device registry and proof-of-possession
│   ├── authentication.py     # Ed25519 & ML-DSA-65 challenge-response authenticator
│   └── recovery.py           # Salted single-use recovery code manager
├── backup/
│   ├── backup_manager.py     # Hot SQLite backup with AES-GCM + HMAC packaging
│   └── restore.py            # Anti-rollback verification and safe restore
├── audit/
│   ├── logger.py             # Cryptographic SHA-256 hash chaining logger
│   ├── checkpoints.py        # Signed external checkpoints (HMAC-SHA-256)
│   └── verifier.py           # Auditor tool detecting tamper, gap, or truncation
├── detection/
│   ├── models.py             # AccessEvent, Incident, and ThreatReport dataclasses
│   ├── clock.py              # Timestamp normalization and monotonic ordering
│   ├── service_graph.py      # Directed access graph & lateral movement detector
│   └── engine.py             # Deterministic explainable threat detection engine
├── messaging/
│   ├── protocol.py           # Frame serialization, AAD binding & replay protection
│   ├── handshake.py          # Ephemeral NIST ML-KEM-768 handshake & session establishment
│   ├── forward_secrecy.py    # Post-compromise forward secrecy harness
│   ├── transport.py          # Bounded chunk framing & out-of-order reassembly
│   └── outbox.py             # Encrypted offline outbox with fail-closed authorization
├── testing/
│   ├── lab.py                # 40-scenario automated security testing laboratory CLI
│   └── phase_1_3_combined_scenario.py # 40-step combined security scenario
├── web/
│   ├── app.py                # FastAPI web server entrypoint
│   ├── schemas.py            # Pydantic request/response models
│   ├── authentication.py     # Local operator authentication & CSRF defense
│   ├── routes/               # Modular REST endpoints (status, cluster, detection, messaging, lab)
│   └── static/               # 100% offline assets (CSS dark cybersecurity theme & Vanilla JS)
└── vault/
    └── resources.py          # Protected resource vault with key versioning
```
