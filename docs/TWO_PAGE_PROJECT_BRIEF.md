# QuantumVault: Two-Page Project Brief

**Hackathon:** Yugaantar DevForge | **Track 4:** "Trust, but verify"  
**Repository:** `ps4-oncemore` | **Release Version:** 4.0.0-final  
**Submission Status:** Technically Verified & Production Ready  

---

<!-- PAGE 1 -->
# PAGE 1: ARCHITECTURE, INNOVATIONS & VERIFIED METRICS

## 1. Executive Summary
QuantumVault is a compromise-resilient post-quantum cryptographic security platform designed to preserve authorized business continuity across dynamic identity changes, credential revocation, physical device loss, and network partitions. Built strictly to NIST FIPS 203 (ML-KEM-768) and NIST FIPS 204 (ML-DSA-65) standards, QuantumVault pairs a lightweight, zero-external-dependency judging adapter (`track4_service.py`) with a distributed multi-process cluster architecture, deterministic explainable threat detection, and an integrated Security Operations Center (SOC) dashboard.

## 2. High-Level Architecture & Trust Model

```
[ UNTRUSTED CLIENT / JUDGING EVALUATOR ]
               |  (JSON stdin / stdout contract)
               v
+------------------------------------------------------------------------+
|                   OFFICIAL ROOT ADAPTER (track4_service.py)            |
|  - Zero-knowledge denial policy: {"decision": "deny"}                  |
|  - NIST FIPS 203 public key coefficient canonicality validation        |
+------------------------------------------------------------------------+
        |                                                |
        v                                                v
+-----------------------------------+   +--------------------------------+
|    MULTI-PROCESS NODE CLUSTER     |   |       SECURITY AUTHORITY       |
|  - Node A, Node B, Node C         |   |  - Monotonic Cluster Epochs    |
|  - Local Policy Enforcement (PEP) |<--|  - Authoritative Revocation Log|
|  - Fail-Closed Partition Guard    |IPC|  - External Epoch Disk Anchor  |
+-----------------------------------+   +--------------------------------+
        |                                                |
        +-----------------------+------------------------+
                                v
+------------------------------------------------------------------------+
|                        PERSISTENT DATA LAYER                           |
|  - SQLite 3 Write-Ahead Logging (WAL) Mode with Atomic Commit Rollback |
|  - AES-256-GCM Encrypted Asset Store with Owner/Asset AAD Binding      |
|  - SHA-256 Tamper-Evident Hash-Chained Audit Trail with HMAC Anchors   |
+------------------------------------------------------------------------+
```

## 3. Core Technical Innovations
1. **NIST FIPS 203 Canonical Key Validation:** Enforces coefficient bounds ($0 \le c < 3329$) across all 768 polynomial coefficients, eliminating malleability vulnerabilities present in generic C wrappers.
2. **Multi-Process Cluster with Crash Anti-Resurrection:** True independent operating system processes (Node A, Node B, Node C) with separate SQLite databases; revoked credentials remain 100% rejected across process crashes and restarts without network re-synchronization.
3. **4-State Key Lifecycle with Asset Rewrapping:** Active master keys rotate gracefully through a 30.0-second grace window, simultaneously rewrapping DEKs under fresh nonces with zero downtime.
4. **Deterministic Explainable Threat Radar:** Replaces non-deterministic black-box ML models with formal graph topology traversal, window-bounded approval validation, and monotonic clock normalization.

## 4. Single Source of Truth Verified Metrics

| Dimension | Measured Metric | Verified Value | Evidence Source |
| :--- | :--- | :--- | :--- |
| **Judging Contract** | Official Toolkit Validator | 12 / 12 PASS (Exit Code 0) | [clean_build_report.json](file:///e:/ps4-oncemore/evidence/phase-4/clean_build_report.json) |
| **Unit & Regression** | Full Automated Test Suite | 190 / 190 PASS (23.75s) | [final_metrics.json](file:///e:/ps4-oncemore/evidence/phase-4/final_metrics.json) |
| **Adversarial Invariants**| Extreme & V6 Adversarial Tests | 49 / 49 PASS (613 adapter calls) | [adversarial_test_results.json](file:///e:/ps4-oncemore/evidence/phase-4/adversarial_test_results.json) |
| **Key Lifecycle** | Rotation Grace Window | 30.0 seconds configured | `quantumvault/crypto/rotation.py` |
| **Cluster Latency** | Authority Durable Commit | 5.32 ms median (7.49 ms p95) | [distributed_revocation.json](file:///e:/ps4-oncemore/evidence/phase-4/distributed_revocation.json) |
| **Revocation Propagation**| Per-Node Delivery Latency | 2.65 ms median across Node A, B, C | [distributed_revocation.json](file:///e:/ps4-oncemore/evidence/phase-4/distributed_revocation.json) |
| **Enforcement Latency** | Confirmed 3-Node Denial | 9.59 ms median (11.91 ms p95) | [distributed_revocation.json](file:///e:/ps4-oncemore/evidence/phase-4/distributed_revocation.json) |
| **Clock Support Range** | Clock Offset Tolerance | [-3600.0s, +3600.0s] verified | [clock_range_results.json](file:///e:/ps4-oncemore/evidence/phase-4/clock_range_results.json) |
| **Threat Detection** | F1 Score (10,000 unseen events)| 0.9433 (Precision 99.78%, Recall 89.44%) | [detection_evaluation.json](file:///e:/ps4-oncemore/evidence/phase-4/detection_evaluation.json) |
| **Detection Accuracy** | False Alerts per 1,000 Benign | 0.6667 (< 1 per 1,000 events) | [detection_evaluation.json](file:///e:/ps4-oncemore/evidence/phase-4/detection_evaluation.json) |
| **Detection Speed** | Median Time to Alert | 0.0141 ms (14.1 microseconds) | [detection_latency.json](file:///e:/ps4-oncemore/evidence/phase-4/detection_latency.json) |
| **Throughput** | Telemetry Processing Rate | 11,407 to 39,799 events/sec | [detection_evaluation.json](file:///e:/ps4-oncemore/evidence/phase-4/detection_evaluation.json) |

---

<!-- PAGE 2 -->
# PAGE 2: COMPREHENSIVE COMPLIANCE, SECURITY & ADVERSARIAL RESILIENCE

## 5. Mandatory Organizer Measurements Summary
- **Configured Grace Period:** 30.0 seconds. Old key version v1 decrypts in-flight reads during grace; expired after cutoff. All assets migrated to v2 in 7.42 ms.
- **Revocation Timing Across Independent OS Nodes:**
  - Authority Commit Latency: 5.32 ms median, 7.49 ms p95, 9.35 ms max.
  - Node Propagation: Node A (2.76 ms), Node B (2.66 ms), Node C (2.56 ms).
  - Node Enforcement Probe: Node A (0.55 ms), Node B (0.48 ms), Node C (0.49 ms).
  - Total Confirmed Denial across cluster: 9.59 ms median, 11.91 ms p95, 12.40 ms max.
- **Supported Clock Difference Range:** [-3600.0s, +3600.0s] (tested $\pm 1\,\text{hour}$ offsets with 100% accurate UTC normalization). Out-of-order arrival buffer window: 10.0 seconds.
- **Unseen Threat Detection Benchmark:** Evaluated on held-out synthetic datasets generated with independent random seeds. On 10,000 events: 99.78% precision, 89.44% recall, 0.9433 F1 score, 0.6667 false alerts per 1,000 benign events, and 14.1 microsecond median alert latency.

## 6. Independent Adversarial Challenge Results
QuantumVault was verified against the full suite of independent adversarial challenges:
- **Easy Challenge (`test-easy.py`):** 5/5 PASS (30 adapter calls) — Basic access, opaque identifiers, reset atomicity.
- **Normal Challenge (`test-normal.py`):** 10/10 PASS (107 adapter calls) — Nonce uniqueness, key state isolation, audit interleaving.
- **Extreme Challenge (`test-extreme.py`):** 16/16 PASS (251 adapter calls) — Non-canonical KEM coefficients, 4-way cohort revocation, 501-operation replay window, two-process recovery races.
- **Challenge V6 (`challenge-u-to-break-v6.py`):** 18/18 PASS (225 adapter calls) — Linearizable revocation, cross-owner ciphertext swap, crash before and after commit.
- **Total Adversarial Invariants:** 49/49 PASSED (0 FAIL, 0 ERROR, 0 SKIP across 613 adapter calls).

## 7. Ground-Rule Compliance Audit

| Requirement | Audit Finding | Status |
| :--- | :--- | :--- |
| **Hardcoded Secrets** | Scanned all repository files; zero hardcoded keys or tokens. | COMPLIANT |
| **AI/ML Runtime** | Zero neural networks, embeddings, LLM APIs, or opaque heuristics. | COMPLIANT |
| **Offline Runtime** | 100% self-contained; zero CDN calls, zero telemetry sockets. | COMPLIANT |
| **Cryptographic Standards** | Native NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) bindings. | COMPLIANT |
| **Clean-Sandbox Build** | Fresh environment built and tested strictly from README.md. | COMPLIANT |

## 8. Honest Limitations & Architectural Boundaries
1. **Clock Skew Assumptions:** Timestamp correction relies on the integrity of telemetry source offset values; unannounced, silent physical clock drift is buffered up to 10 seconds.
2. **Session Resumption Policy:** Session resumption is intentionally omitted to guarantee information-theoretic forward secrecy across device compromise incidents.
3. **Cluster IPC:** Inter-node communication operates over authenticated local pipes and loopback sockets; multi-datacenter WAN deployments would require mutual TLS (mTLS).

## 9. Why QuantumVault Wins Track 4
1. **Unbroken Correctness:** 255/255 total tests passing (12 validator, 190 regression, 49 adversarial, 4 cluster scenarios).
2. **Mathematical Post-Quantum Rigor:** Strict implementation of NIST FIPS 203 with coefficient canonicality checks.
3. **Genuine Multi-Process Engineering:** Real OS processes for Node A, B, and C with durable WAL persistence and sub-10ms confirmed cluster enforcement.
4. **Reproducible Excellence:** Fully documented single source of truth metrics in `evidence/phase-4/final_metrics.json`.
