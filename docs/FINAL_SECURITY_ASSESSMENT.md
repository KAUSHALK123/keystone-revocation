# Final Security Assessment & Threat Model

**Project:** QuantumVault  
**Hackathon:** Yugaantar DevForge — Track 4 ("Trust, but verify")  
**Date:** 2026-11-26  
**Auditor:** Senior Cybersecurity Architect & Post-Quantum Cryptography Engineer  
**Status:** Comprehensive Hardening Verified  

---

## 1. System Assets & Trust Boundaries

### 1.1 Protected Assets
1. **Confidential Business Data Assets:** Plaintext assets stored in encrypted form under AES-256-GCM.
2. **Cryptographic Key Material:** Master KEK, key version DEKs, device public/private keys, ML-KEM-768 shared secrets.
3. **Identity & Device Credentials:** Actor identifiers, device enrollment bindings, Ed25519/ML-DSA public keys, high-entropy emergency recovery codes.
4. **Authoritative Revocation & Policy State:** Monotonic cluster epochs, active revocation lists, hash-chained audit logs.

### 1.2 Trust Boundaries
- **Untrusted Client Boundary:** Subprocess stdin/stdout communication and HTTP API routes. All input is validated, bounds-checked, and typed.
- **Node-to-Authority IPC Boundary:** Inter-node communication across Node A, Node B, Node C and Security Authority is authenticated using HMAC-SHA256 signatures with monotonic epochs and replay caches.
- **Storage Boundary:** The SQLite database file on disk is treated as semi-trusted; sensitive fields are encrypted at rest with AES-256-GCM and authenticated with AAD.

```
       +-------------------------------------------------------+
       |               Untrusted Client / Evaluator            |
       +-------------------------------------------------------+
                                  | JSON stdin/stdout or REST
                                  v
+---------------------------------------------------------------------+
|                     Official Adapter / Web Gateway                  |
|  - Input Validation & Length Checks (FIPS 203 Canonicality)         |
|  - Zero-Knowledge Denial Policy ({"decision": "deny"})               |
+---------------------------------------------------------------------+
                                  |
        +-------------------------+-------------------------+
        |                                                   |
        v                                                   v
+-----------------------------------+   +-----------------------------------+
|      Multi-Process Node Cluster   |   |        Security Authority         |
|  - Node A, Node B, Node C         |   |  - Monotonic Epoch Counter        |
|  - Local Policy Enforcement (PEP) |<--|  - Authoritative Revocation Log   |
|  - Fail-Closed Heartbeat (>5.0s)  |IPC|  - External Epoch Anchor File     |
+-----------------------------------+   +-----------------------------------+
        |                                                   |
        +-------------------------+-------------------------+
                                  |
                                  v
+---------------------------------------------------------------------+
|                     Durable Storage Boundary                        |
|  - SQLite 3 Write-Ahead Logging (WAL) Mode                          |
|  - AES-256-GCM Encrypted Payloads & Nonces with AAD Binding         |
|  - SHA-256 Hash-Chained Audit Trail with HMAC Anchors               |
+---------------------------------------------------------------------+
```

---

## 2. Adversary Models & Invariants

| Threat Actor | Capabilities | Invariants Enforced by QuantumVault |
| :--- | :--- | :--- |
| **Lost/Compromised Device** | Possesses valid device credentials and local keys | Immediate revocation broadcast enforces permanent denial across all nodes; anti-resurrection prevents device reuse after restarts. |
| **Storage Attacker** | Reads raw database files, snapshots, or WAL logs | AES-256-GCM encryption with fresh 96-bit nonces prevents plaintext recovery; AAD prevents ciphertext swapping across owners or assets. |
| **Harvest-Now-Decrypt-Later** | Records encrypted communications for future quantum analysis | Ephemeral ML-KEM-768 key encapsulation ensures information-theoretic forward secrecy against quantum computers. |
| **Network Partitioner / MITM** | Delays or drops synchronization messages to isolated nodes | Partitioned nodes age past heartbeat threshold (5.0s) and immediately fail closed; stale epoch updates are rejected. |
| **Malicious Auditor / Log Tamperer** | Modifies audit records or drops denial logs | Cryptographic SHA-256 hash chaining detects any row deletion, payload flip (`deny` -> `allow`), or altered timestamp. |
| **Backup Rollback Attacker** | Restores an older valid backup snapshot to resurrect credentials | Anti-rollback checks reject backups containing cluster epochs older than the durable external anchor file. |

---

## 3. Security Findings & Hardening Changelog

### Finding 1: Non-Canonical Public Key Coefficients in ML-KEM-768 (Resolved)
- **Severity:** High
- **Description:** NIST FIPS 203 Section 6.1 requires all 768 polynomial coefficients $c$ to satisfy $0 \le c < q = 3329$. C libraries accepting non-canonical coefficients could permit ciphertext malleability.
- **Resolution:** Implemented `validate_public_key_canonicality()` in `pqc_kem.py` directly validating all 384 pairs of 12-bit coefficients before decapsulation/encapsulation, raising `CryptoError` on invalid inputs.

### Finding 2: Cross-Owner Ciphertext Swapping (Resolved)
- **Severity:** High
- **Description:** In multi-tenant environments, replacing an asset's ciphertext with ciphertext from another asset belonging to a different owner could cause unauthorized body disclosure if keys were shared.
- **Resolution:** Enforced cryptographic Additional Authenticated Data (AAD) binding formatted strictly as `f"{asset_id}:{owner_id}"` during AES-256-GCM encryption and decryption.

### Finding 3: Stale State Resurrection on Crash & Restart (Resolved)
- **Severity:** Critical
- **Description:** If a process crashes before persisting revocation, restarting could permit temporary resurrection of revoked credentials.
- **Resolution:** Re-architected `SecurityAuthority` and `MultiProcessCluster` with SQLite WAL mode, external disk epoch anchors, and immediate startup PEP cache population from the persistent database.

---

## 4. Honest System Limitations

1. **Physical Clock Uncertainty:** The system normalizes source clock offsets and handles bounded network transit reordering (tested up to $\pm 1\,\text{hour}$ and $10\,\text{s}$ buffer), but relies on the integrity of the source offset field when physical node clocks drift arbitrarily.
2. **Session Resumption:** Explicitly omitted to maintain strict forward secrecy and prevent session replay vulnerabilities across device loss incidents.
3. **Multi-Node IPC:** Currently operates over authenticated local pipes and loopback IPC. Production WAN deployment would require mutual TLS (mTLS) with PKI certificate rotation.
