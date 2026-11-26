# Trust, but verify — QuantumVault Project Brief

## Page 1: USP, Architecture, and Fallback Video

**Project:** QuantumVault  
**Team:** [USER / Collaborator Team Name — User Action Required: Insert Full Names]  
**Repository and commit:** `https://github.com/KAUSHALK123/keystone-revocation.git` (Commit: `ce1655c`)  
**Demo entry point:** `python -m quantumvault.web.app` (Local SOC: `http://127.0.0.1:8000`) | Standalone Adapter: `python track4_service.py`

### Unique Selling Proposition (USP)
QuantumVault protects sensitive organizational assets and end-to-end communications across zero-trust distributed infrastructure subject to lost devices, key rotations, node partitions, and active adversary lateral movement. It eliminates credential resurrection by coupling durable SQLite WAL consensus with immediate fail-closed Policy Enforcement Points across distributed cluster nodes. QuantumVault is the first hackathon architecture to pair standardized NIST post-quantum key encapsulation (ML-KEM-768 / FIPS 203) and digital signatures (ML-DSA-65 / FIPS 204) with deterministic, explainable, graph-based lateral movement detection that achieves 100% precision with zero AI/ML opacity.

### Architecture
QuantumVault enforces a multi-tiered zero-trust security architecture:
1. **Core Adapter & PEP Interface (`track4_service.py`):** Standalone zero-dependency runtime fulfilling Adapter Contract v1 (`setup`, `read`, `revoke`, `audit`, `protected_read`).
2. **Post-Quantum Cryptographic Engine (`quantumvault/crypto`):** Standardized NIST ML-KEM-768 key encapsulation with HKDF-SHA256 session key derivation, NIST ML-DSA-65 signatures, and AES-256-GCM authenticated encryption. Enforces in-place RAM zeroization of ephemeral private keys for post-compromise forward secrecy.
3. **Distributed Policy Authority (`quantumvault/distributed`):** Central authority issuing monotonic epoch updates; distributed nodes (Node A, B, C) caching revocations with strict fail-closed enforcement upon network partition.
4. **Deterministic Threat Detection (`quantumvault/detection`):** Context-aware evaluation reconciling telemetry against formal approvals (`approvals.json`) and service dependency graphs. Classifies lateral movement sequences (`reports → billing → archive → identity`) without neural network uncertainty.
5. **Security Operations Center Dashboard (`quantumvault/web`):** Offline-capable, lightweight operator console serving live cluster topology, threat radar playback, and interactive post-quantum messaging.

```
┌────────────────────────────────────────────────────────────────────────┐
│  QUANTUMVAULT ZERO-TRUST ARCHITECTURE                                  │
│  [Clients/Devices] ──(ML-KEM-768/AES-GCM)──> [Policy Enforcement PEP] │
│                                                      │                 │
│  [Security Authority] <──(Epoch Sync/Revocation)────┤                 │
│         │                                            ▼                 │
│  [Audit Merkle Log] <──(HMAC Checkpoints)── [Resource Vault (SQLite)]  │
└────────────────────────────────────────────────────────────────────────┘
```

### Accessible Five-Minute Fallback Video Link
**Video link:** `[PENDING USER UPLOAD — Insert Public/Unlisted URL (YouTube/Google Drive)]`  
**Duration:** 05:00 minutes  
**Access checked:** `[Pending Final Link Verification — Ensure public access without login]`  

**Walkthrough Outline:**  
The demonstration covers 5 phases: (1) Architecture & PQC intro; (2) Distributed node revocation propagation and fail-closed partition; (3) Explainable Threat Radar isolating lateral movement in the 22-event practice dataset; (4) Post-quantum messaging handshake, AEAD recipient binding, and forward-secrecy verification; (5) Automated laboratory runner verifying 40/40 scenarios live.

**Observed outcome:** Passes 12/12 official validator checks, 171/171 automated unit/integration tests, 40/40 security lab scenarios, and achieves 100.0% accuracy ($F_1 = 1.000$) on the practice telemetry dataset with median alert latency of 26.9 microseconds. Evidence verified in repository under `evidence/phase-2/`.

<div style="page-break-before: always;"></div>

## Page 2: One-Page Threat Model

### Assets
1. **Protected Resource Plaintext:** Confidential document bodies requiring confidentiality and integrity (AES-256-GCM).
2. **Cryptographic Key Material:** Master Vault KEK, active DEKs, ephemeral ML-KEM-768 shared secrets, and device identity keys (ML-DSA-65 / Ed25519).
3. **Durable Authorization State:** Active identities, device enrollments, single-use recovery code hashes, and monotonic cluster epochs.
4. **Audit & Incident Telemetry:** Append-only access logs and incident alerts requiring non-repudiation and tamper-evidence.

### Adversaries
1. **Stolen-Device Opportunist:** Possesses a compromised physical endpoint with active local credentials attempting access post-revocation.
2. **Network Eavesdropper / Man-in-the-Middle:** Intercepts, delays, replays, reorders, or tampers with transit ciphertext packets or recipient metadata.
3. **Compromised Internal Microservice:** Uses legitimate service credentials to pivot laterally toward out-of-scope enterprise services.
4. **Privileged Insider / Rogue Administrator:** Attempts unauthorized role escalation or historical audit log truncation without formal change approvals.
5. **Future Quantum Adversary:** Harvests encrypted network transcripts today to retroactively decrypt them with cryptanalytically relevant quantum computers (SNDL).

### Trust Boundaries
- **Boundary 1 (Identity Check / PEP):** Demarcates untrusted incoming client requests from internal service execution. Identity and device authentication must precede resource access.
- **Boundary 2 (Cluster Authority Boundary):** Separates the primary Security Authority from local service worker nodes; policy state propagates via authenticated monotonic epochs.
- **Boundary 3 (Storage & Audit Boundary):** Separates application memory from persistent SQLite databases and isolated external HMAC audit checkpoints.

### Assumptions
- **Host OS & Memory Isolation:** Underlying operating system enforces process isolation; local disk permissions prevent unauthorized direct SQLite database file tampering.
- **Cryptographic Hardness:** Module-Lattice Learning with Errors (MLWE) is intractable for post-quantum adversaries; AES-256 and SHA-256 are collision/pre-image resistant.
- **Clocks & Uncertainty:** Node clocks are synchronized within a bounded uncertainty window ($\pm 2000\text{ ms}$); source offsets are recorded and compensated at ingestion.

### Defenses
- **Quantum-Safe Handshake & PFS:** Ephemeral ML-KEM-768 session establishment; ephemeral secrets are immediately overwritten in RAM, ensuring past sessions cannot be decrypted if long-term signing keys are stolen later.
- **Immediate Distributed Revocation:** Cluster coordinator commits revocation to durable authority, invalidates local PEP caches, and verifies real denial across all nodes within milliseconds. Unreachable nodes fail closed.
- **Explainable Lateral Movement Radar:** Purely deterministic rule engine cross-references service edges against approvals, clustering multi-hop sequences while distinguishing isolated denials.
- **Tamper-Evident Hash Chains & Out-of-Band Checkpoints:** Audit records maintain SHA-256 forward links validated against isolated HMAC checkpoints. Any truncation or modification is flagged immediately.

### Exclusions and Remaining Risks
- **Unsupported Feature:** Session resumption is intentionally **DISABLED BY POLICY** (`not supported`); session ticket theft attack surfaces are completely eliminated.
- **Endpoint Memory Compromise:** Active plaintext in host memory during processing cannot be protected if the OS kernel is completely subverted.
- **Synthetic Log Limitation:** 100% precision on the 22-event practice dataset verifies deterministic logic, but does not represent an infinite production threat distribution.
