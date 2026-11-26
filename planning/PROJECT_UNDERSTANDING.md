# QuantumVault — Project Understanding & Problem Analysis
**Hackathon:** Yugaantar DevForge | **Track:** Track 4: "Trust, but verify"  
**Project Working Name:** QuantumVault  
**Document Status:** Approved Architectural Planning (Phase-U)

---

## 1. Executive Summary & Context

Yugaantar DevForge is a premier multi-track engineering hackathon featuring specialized technical tracks. **Track 4: "Trust, but verify"** focuses on the intersection of post-quantum cryptography (PQC), robust identity and access management (IAM), distributed consistency, failure resilience, and explainable security telemetry anomaly detection.

The project under development is **QuantumVault**: a compromise-resilient enterprise security platform engineered to guarantee confidential data access and secure communication across key rotations, device revocations, network partitions, and host crashes, while providing deterministic, explainable telemetry anomaly detection without artificial intelligence or machine learning.

### Phased Execution Strategy
- **Phase-U (Current Phase):** Complete project understanding, technical research, architecture definition, cryptographic API verification, and implementation planning. No production application code, frontend development, or ad-hoc dependencies are implemented in this phase.
- **Phase-B (Subsequent Phase):** Rigorous, milestone-driven prototype implementation, cryptographic integration, multi-node simulation, test harness verification, and final submission packaging.

---

## 2. Core Problem Statement Breakdown

### 2.1 The Mission Brief
> "Build one working prototype that protects messages or files as keys, devices and user permissions change. Use its access logs to show an operator when an identity gains unexpected privileges or starts accessing other services."

In enterprise infrastructures, security is not static. Identity state, cryptographic keys, and device trust continuously evolve. Typical systems fail catastrophically during state transitions:
1. **Key Transitions:** Rotating a key often interrupts in-flight transactions or leaves historical ciphertext unreadable.
2. **Device Loss:** Revoking a lost device either fails to propagate across all edge nodes or accidentally locks out the legitimate user from their own data.
3. **Infrastructure Failures:** Node crashes during key update transactions lead to split-brain states or re-enable previously revoked credentials upon reboot.
4. **Insider & Credential Abuse:** Attackers with stolen valid credentials traverse service boundaries undetected because individual authorization checks pass in isolation.

### 2.2 What QuantumVault IS vs. What It IS NOT

| Feature Dimension | What QuantumVault IS NOT | What QuantumVault IS |
| :--- | :--- | :--- |
| **Cryptographic Scope** | A quantum computer simulation or custom, unverified encryption algorithm. | A post-quantum secure platform implementing standardized **ML-KEM-768** (FIPS 203) for key encapsulation alongside authenticated symmetric encryption. |
| **Device Management** | A mobile phone tracker, remote spyware, or covert endpoint extractor. | An enterprise device identity registry managing cryptographic device bindings, credential revocation, and authorized re-enrollment. |
| **Threat Detection** | A probabilistic, opaque AI/ML black box or neural network. | A deterministic, explainable rules-and-graph detection engine correlating change approvals, service edges, and clock skew. |
| **Operational Model** | A cloud-dependent SaaS requiring external Firebase/AWS APIs. | A self-contained, offline-capable architecture designed for read-only sandboxed containers with transactional local state. |

---

## 3. The QuantumVault Vision & Unique Selling Proposition (USP)

### Proposed USP
> **"A compromise-resilient post-quantum security platform that preserves authorized access during key changes, device loss, network partitions, and infrastructure failures, while providing verifiable recovery and explainable detection of suspicious identities."**

### Architectural Pillars
1. **Post-Quantum Cryptographic Boundary:** Hybrid-ready cryptographic architecture using NIST ML-KEM-768 for post-quantum key encapsulation and HMAC-SHA-256 for cryptographic challenge proofs.
2. **Deterministic Identity & Access Control:** Fine-grained role- and attribute-based access control with immediate, immutable revocation propagation across multi-node services.
3. **Crash-Safe Transactional Persistence:** SQLite-backed write-ahead log (WAL) transactional state management with atomic commits, ensuring zero credential resurrection after unexpected process termination.
4. **Verifiable Audit Logging:** Hash-chained, tamper-evident audit trail immune to log injection and formatting manipulation.
5. **Explainable Security Telemetry Engine:** Anomaly detection combining change-control authorization correlation (`approvals.json`), directed service-graph path analysis, and physical clock skew compensation.
6. **Strict Offline Evaluation Compliance:** 100% self-contained standalone execution matching the official Linux judging container specifications.

---

## 4. Analysis of Organizer Toolkit & Reference Materials

### 4.1 Official References Inspected
- **Official Track 4 Portal:** `https://rentry.co/uio6w6kn` (Universal hackathon rules, 100-point evaluation rubric, and track problem statement).
- **Official GitHub Toolkit:** `https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit` (Release v1.0.0, commit `8901dfb`).
- **Workspace Reference:** `details.txt` (74 KB comprehensive architectural reference generated from local checkout and execution).

### 4.2 Toolkit Verification & Validation Results
1. **Local Conformance Test Harness (`validate.py`):**
   - Verified that `validate.py` enforces a 64 KiB buffer cap per output stream, spawns isolated daemon threads to drain stdout/stderr, injects randomized hex tokens, and executes 12 distinct verification steps across two clean temporary directories.
   - Confirmed exit codes: `0` (Pass), `1` (Behavioral/Leakage failure), `2` (Setup/Crash/Timeout failure), `3` (Format/JSON failure).
2. **Official Adapter Contract (`docs/adapter-v1.md`):**
   - The judging harness invokes `track4_service.py` as a **brand-new operating system process for each request**.
   - Input: Exactly one JSON object on `stdin`.
   - Output: Exactly one JSON object on `stdout` followed by a newline; all debug logs strictly on `stderr`.
   - Mandatory Operations: `setup`, `read`, `revoke`, `audit`, `protected_read`.
3. **Practice Dataset (`practice/`):**
   - Verified all 22 events in `practice/events.csv`, ground truth labels in `practice/labels.csv`, and change approvals in `practice/approvals.json`.
   - Analysis proved key nuances: `evt-014` arrives before `evt-013` (network delay); `evt-015` exhibits +2000 ms clock offset (200 ms physical transit time); `evt-010`-`012` constitute a candidate lateral movement sequence across `reports` -> `billing` -> `archive` -> `identity`.
4. **Post-Quantum Cryptography Verification (`pqcrypto` v0.4.0):**
   - Verified that in `pqcrypto` v0.4.0 (PyPI release Jan 2026), the ML-KEM-768 API is located at `pqcrypto.kem.ml_kem_768`.
   - Crucial API distinction: the functional methods are **`encaps(pk)`** and **`decaps(sk, ct)`**, NOT outdated method names like `encapsulate()`. Constants include `PUBLIC_KEY_SIZE` (1184 bytes), `CIPHERTEXT_SIZE` (1088 bytes), `SHARED_SECRET_SIZE` (32 bytes).

---

## 5. Strict Competition Ground Rules

To ensure complete compliance with hackathon governance, QuantumVault adheres to the following non-negotiable boundaries:
- **Zero AI/ML in Core Logic:** Anomaly detection is purely rule-based, graph-based, and statistical. No scikit-learn, PyTorch, TensorFlow, or LLMs.
- **Zero Hardcoded Secrets / Bypass Flags:** Keys and tokens are dynamically ingested or generated via CSPRNG (`secrets` module).
- **Standardized Cryptography Only:** Standardized ML-KEM-768 and HMAC-SHA-256; zero custom ciphers.
- **Clean Sandbox Scope:** Testing occurs strictly within the assigned mock service environment; no external network requests.
- **Air-Gapped Operation:** The entire prototype operates offline without downloading runtime dependencies.

---

## 6. Phase-U Conclusion

The problem domain, requirements, constraints, and judging mechanics are fully understood. Architectural planning proceeds with zero ambiguity regarding the adapter contract, evaluation criteria, or cryptographic expectations.
