# QuantumVault

**A compromise-resilient post-quantum security platform that preserves authorized access during key changes, device loss, network partitions and infrastructure failures, while providing verifiable recovery and explainable detection of suspicious identities.**

**Hackathon:** Yugaantar DevForge | **Track 4:** "Trust, but verify"  
**Version:** 1.3.0 (Phase 1.3 Backend, Detection & Post-Quantum Messaging Complete)

---

## 1. Project Overview

QuantumVault is an enterprise-grade security platform designed to protect confidential data assets across dynamic identity and cryptographic transitions. 

In Phase 1.3, QuantumVault has completed the full Track 4 backend architecture, addressing all 12 hackathon objectives:
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
- **Session Resumption Policy (Objective 12):** Explicitly declared and enforced as **UNSUPPORTED BY POLICY** to eliminate persistent session ticket and PSK theft attack surfaces; fresh ephemeral ML-KEM-768 handshakes enforced on every connection.
- **Unified Security Testing Laboratory CLI:** `python -m quantumvault.testing.lab` with 40 built-in scenarios covering all subsystems (**40/40 PASSED**).
- **40-Step Combined Security Resilience Demonstration:** Comprehensive headless integration test proving end-to-end security resilience (**40/40 steps PASSED** in 1,575.7 ms).
- **Official Judging Adapter Conformance:** Root adapter `track4_service.py` satisfies all 12 checks of official `validate.py` harness with exit code 0.

---

## 2. Supported Runtimes & Dependencies

- **Python Runtime:** Python 3.12 (standard judging runtime) or Python 3.11+.
- **Core Dependencies (`requirements-core.txt`):**
  - `pqcrypto==0.4.0` (Native bindings for NIST ML-KEM-768 / FIPS 203 and NIST ML-DSA-65 / FIPS 204)
  - `cryptography>=42.0.0` (AES-256-GCM authenticated cipher & Ed25519 signatures)
- **Zero Network Invocations:** The judging adapter `track4_service.py` requires zero external network connections or cloud services.
- **Self-Contained Storage:** SQLite 3 WAL persistence with clean atomic transactions.

---

## 3. Quickstart & Adapter Usage

### 3.1 Clone & Environment Setup
```bash
git clone https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit.git references/track4-toolkit
pip install -r requirements-core.txt
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

### 3.3 Running the Official Validator
```bash
python references/track4-toolkit/validate.py --entry track4_service.py
# Local lost-device validator: 12/12 PASS
```

### 3.4 Running the Unified Security Testing Laboratory
```bash
# List all 40 registered scenarios
python -m quantumvault.testing.lab --list

# Run all 40 scenarios
python -m quantumvault.testing.lab --run-all

# Run a specific scenario
python -m quantumvault.testing.lab --scenario candidate_lateral_movement_sequence
python -m quantumvault.testing.lab --scenario forward_secrecy_post_compromise
```

### 3.5 Running the 40-Step Combined Security Scenario
```bash
python -c "from quantumvault.testing.phase_1_3_combined_scenario import Phase13CombinedScenario; sc = Phase13CombinedScenario(); res = sc.run(); print(f'{res.steps_passed}/{res.total_steps} PASS in {res.execution_time_ms:.1f}ms')"
```

### 3.6 Running the Full Automated Test Suite
```bash
python scripts/record_phase_1_3_test_suite.py
# Ran 156 tests in 38.28s. Failures: 0, Errors: 0
```

---

## 4. Verification & Testing Suite

### 4.1 Running the Official Organizer Validator
Verify QuantumVault against the organizer's conformance checker:
```bash
python references/track4-toolkit/validate.py --entry track4_service.py
```
*Expected Result:* All 12 checks output `PASS` with exit code 0.

### 4.2 Running the Full Automated Test Suite (123 Tests)
Execute the complete 123-test independent verification suite covering Phase 1.1 + Phase 1.2 components:
```bash
python -m unittest discover tests -v
```
*Expected Result:* `Ran 123 tests ... OK` (100% PASS, 0 failures, 0 errors).

### 4.3 Running the 23-Step Grand Adversarial Scenario
Execute the headless end-to-end security failure and resilience scenario:
```bash
python -m unittest tests/test_grand_scenario.py -v
```
*Expected Result:* `test_complete_23_step_grand_scenario ... ok` (23/23 steps PASS).

### 4.4 Running Performance Benchmarks
Collect high-resolution empirical latency baselines across all Phase 1.2 subsystems:
```bash
python scripts/benchmark_phase_1_2.py
```

---

## 5. Performance Baselines (Phase 1.2)

| Benchmark Domain | Metric | Measured Value | Standard / Limit |
| --- | --- | --- | --- |
| **Device Authentication** | Keypair Generation | **0.0607 ms** | Ed25519 CSPRNG |
| | Challenge-Response Roundtrip | **0.3238 ms** | Sig verify + single-use |
| **Account Recovery** | 5 Salted Codes Generation | **2.1268 ms** | CSPRNG + SHA-256 |
| | Atomic Code Verification & Consume | **2.1898 ms** | Timing-safe compare |
| **Key Rotation & Rewrapping** | 100 Assets Total Rotation | **7.42 ms** | **0.074 ms / asset** |
| **3-Node Propagation** | Total 3-Node Propagation Time | **0.0235 ms** | Sub-millisecond sync |
| **Backup & Restore** | Hot Backup Creation (AES-GCM + HMAC) | **20.34 ms** | Consistent online copy |
| | Anti-Rollback Verify & Restore | **11.17 ms** | PRAGMA integrity check |
| **Audit Log Integrity** | 1,000 Events Verification | **7.24 ms** | **0.0072 ms / event** |

---

## 6. Directory Layout

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
│   ├── authentication.py     # Ed25519 challenge-response authenticator
│   └── recovery.py           # Salted single-use recovery code manager
├── backup/
│   ├── backup_manager.py     # Hot SQLite backup with AES-GCM + HMAC packaging
│   └── restore.py            # Anti-rollback verification and safe restore
├── audit/
│   ├── logger.py             # Cryptographic SHA-256 hash chaining logger
│   ├── checkpoints.py        # Signed external checkpoints (HMAC-SHA-256)
│   └── verifier.py           # Auditor tool detecting tamper, gap, or truncation
└── vault/
    └── resources.py          # Protected resource vault with key versioning
```
