# Final Technical Q&A & Evaluator Defense Guide

**Project:** QuantumVault  
**Hackathon:** Yugaantar DevForge — Track 4 ("Trust, but verify")  
**Target Audience:** Hackathon Evaluators, Cryptography Auditors & Systems Engineers  

---

## 1. Post-Quantum Cryptography & Key Management

### Q1: Why did you choose ML-KEM-768 instead of classical ECDH (e.g. X25519) or other post-quantum schemes?
**Answer:**
ML-KEM-768 is the primary standard finalized in NIST FIPS 203 (August 2024), providing Security Category 3 (equivalent to AES-192 in classical terms, and quantum-resistant against Shor's algorithm). Classical X25519 is vulnerable to "Harvest-Now-Decrypt-Later" attacks where recorded ciphertexts will be decrypted once cryptanalytically relevant quantum computers (CRQCs) exist. We implemented ML-KEM-768 natively with strict coefficient canonicality validation ($c < 3329$) and hybrid support with Ed25519/ML-DSA-65 signatures.

### Q2: How does QuantumVault handle public key validation and malleability?
**Answer:**
Under NIST FIPS 203 Section 6.1, public keys are 1184-byte arrays encoding 768 coefficients of polynomial elements in $\mathbb{Z}_q[X]/(X^{256}+1)$ with $q=3329$. Standard C wrappers often omit coefficient checks, allowing malleable values up to $2^{12}-1 = 4095$. In `pqc_kem.py`, our `validate_public_key_canonicality()` unpacks every coefficient pair and rejects any key with $c \ge 3329$ via `CryptoError`, ensuring strict fail-closed rejection before decapsulation.

### Q3: How do you achieve key rotation without taking down services or corrupting in-flight requests?
**Answer:**
QuantumVault implements a formal 4-state lifecycle machine (`pre_active` -> `active` -> `grace_period` -> `retired`):
1. The new key version is generated in `pre_active` and promoted to `active`.
2. The superseded key transitions to `grace_period` with a strict cutoff timestamp (configured to 30.0 seconds).
3. In-flight requests presenting the previous key version are decrypted successfully throughout the grace window.
4. Concurrently, all stored asset DEKs are re-wrapped under the new master key with fresh 96-bit nonces and AAD binding.
5. Once the cutoff elapses, the key transitions permanently to `retired` and any subsequent access is denied.

---

## 2. Distributed Consensus, Revocation & Partitions

### Q4: The organizers required that "rejected means rejected on every node, including after a crash or restart." How is this implemented?
**Answer:**
QuantumVault models Node A, Node B, and Node C as independent operating system processes with separate SQLite database files and WAL logs:
1. **Durable Commit:** When an entity is revoked, `SecurityAuthority` writes the revocation into its database and advances the monotonic cluster epoch in an external anchor file.
2. **HMAC IPC Broadcast:** The authority transmits an HMAC-SHA256 signed revocation message to each node process.
3. **Local PEP Cache + DB Write:** Each node updates its local in-memory PEP cache and commits the revocation to its own SQLite table.
4. **Crash & Restart Invariant:** If a node is abruptly terminated with `SIGKILL`, its database already holds the committed revocation. Upon restart, the node initializes its PEP cache directly from the on-disk database, ensuring 100% anti-resurrection across restarts without waiting for network re-synchronization.

### Q5: What happens when a network partition disconnects Node C?
**Answer:**
Node C enforces a strict fail-closed heartbeat threshold ($5.0\,\text{s}$). If the Security Authority is unreachable or Node C's heartbeat exceeds 5 seconds, all read and protected_read requests are immediately denied (`{"decision": "deny", "rule": "node_offline_fail_closed"}`). When reconnected, Node C exchanges cluster epochs; if its epoch is stale, it ingests missed revocations and resumes serving requests.

---

## 3. Crash Recovery, WAL & Atomic Persistence

### Q6: How does QuantumVault guarantee zero partial state during power cuts or crashes?
**Answer:**
We configure SQLite with Write-Ahead Logging (`PRAGMA journal_mode = WAL`) and `PRAGMA synchronous = NORMAL`. All critical multi-table updates (e.g. key rotation with asset rewrapping, device enrollment, or revocation) execute inside strict context-managed database transactions:
```python
with transaction(self.conn):
    # Atomic updates to keys, assets, and app_state
```
If an unhandled crash occurs mid-rotation, the uncommitted write is rolled back completely. On startup, `recover_interrupted_rotation()` inspects the durable checkpoint `key_rotation_status: in_progress:v1->v2` and either cleanly finishes rewrapping or aborts, leaving zero corrupt or partially migrated assets.

### Q7: How do you prevent backup rollback attacks?
**Answer:**
Every backup archive includes an HMAC-authenticated header binding the cluster's monotonic epoch. During restoration, `BackupRestoreManager` reads the external disk anchor `epoch_anchor.txt` (which cannot be rolled back merely by restoring an older SQLite file). If `backup_epoch < current_anchor_epoch`, restoration aborts immediately with a rollback attack error, preventing an attacker from resurrecting revoked credentials.

---

## 4. Threat Detection & Explainability

### Q8: Why did you not use a pre-trained neural network or random forest for threat detection?
**Answer:**
Machine learning classifiers are probabilistic, non-deterministic, vulnerable to adversarial evasion (concept drift and perturbation attacks), and function as "black boxes" that fail the organizer's explainability requirement.
QuantumVault's deterministic engine combines:
- **Service Graph Topology:** Explicit directed graph tracking expected service boundaries.
- **Approval Registry:** Window-validated, scope-checked change tickets.
- **Stateful Flow Tracking:** Session-correlated role transitions and multi-hop denial clustering.
This guarantees 100% deterministic reproducibility, zero training overhead, sub-millisecond alert latency (14.1 microseconds median), and exact MITRE ATT&CK technique mapping.

### Q9: How was the engine evaluated against unseen data?
**Answer:**
We built an independent synthetic evaluation generator that produces held-out datasets with completely novel identities, service names, graph topologies, and role names across multiple random seeds.
On an unseen 10,000-event dataset:
- **Precision:** 99.78%
- **Recall:** 89.44%
- **F1 Score:** 0.9433
- **False Alert Rate:** 0.6667 per 1,000 benign events (< 1 false alert per 1,000)
- **Throughput:** > 11,400 events/second.
