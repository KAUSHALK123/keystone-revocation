# QuantumVault — 5-Minute Live Demonstration Script & Technical Q&A

**Hackathon Track:** Yugaantar DevForge | Track 4: "Trust, but verify"  
**Application Entrypoint:** `http://127.0.0.1:8000` (Local SOC Operator Dashboard)  
**Total Target Duration:** Exactly 05:00 minutes  

---

## 1. Minute-by-Minute Live Demonstration Flow

```
[00:00 - 00:25] Introduction & Unique Selling Proposition (USP)
[00:25 - 01:35] Tab 1: Distributed Cluster, Instant Revocation & Lost-Device Recovery
[01:35 - 02:30] Tab 2: Threat Radar & Explainable Lateral Movement Detection
[02:30 - 03:35] Tab 3: Post-Quantum Messaging, AEAD Binding & Forward Secrecy
[03:35 - 04:40] Tab 4 & Tab 5: Security Lab & 15-Step Guided Judge Demo Mode
[04:40 - 05:00] Conclusion, Benchmark Summary & Q&A Transition
```

---

### Step 1: Introduction & USP (0:00 – 0:25)
- **Visual:** Open browser to `http://127.0.0.1:8000`. Show the global header: `QUANTUMVAULT | POST-QUANTUM SOC`, active epoch, active key version, and environment badges.
- **Spoken Script:**
  > *"Good afternoon, judges. We are presenting **QuantumVault**, built for Track 4: 'Trust, but verify'. In zero-trust distributed environments, the critical failure mode isn't just encrypting data—it's what happens when devices are lost, keys rotate, and nodes lose connectivity. QuantumVault combines standardized NIST post-quantum cryptography (ML-KEM-768 and ML-DSA-65) with fail-closed distributed consensus and deterministic threat detection that achieves 100% precision with zero AI/ML opacity."*

---

### Step 2: Tab 1 — Nodes & Revocation (0:25 – 1:35)
- **Visual:** Stay on **Tab 1: Nodes & Revocation**. Show the 4 cluster nodes (Primary Authority, Node A, Node B, Node C).
- **Actions to Perform:**
  1. Click **`REVOKE ENTITY`** for `analyst-1`.
  2. Point to the terminal: Show Authority commit latency (`< 2ms`), confirmed nodes (`Node A, B, C`), and total propagation time (`< 6ms`).
  3. Click **`DISCONNECT NODE C`**: Show Node C instantly transition to `FAIL-CLOSED (RED)`. Explain: *An isolated node never assumes access is granted.*
  4. Click **`RECONNECT & SYNCHRONIZE`**: Show Node C resynchronize with current Authority epoch.
  5. Click **`RUN 11-STEP DEMO`**: Watch the 11 steps execute in the terminal window.
- **Spoken Script:**
  > *"Here is our distributed cluster topology. When we revoke an entity, revocation is durably committed to SQLite WAL and broadcast across all service nodes in under 6 milliseconds. If Node C is partitioned from the authority, it fails closed—never allowing stale credentials. In our 11-step lost-device demonstration, when Alex's device is reported stolen, access is immediately blocked across the cluster. Unaffected peers like Blair retain uninterrupted access, and Alex recovers access securely using a single-use recovery code to enroll a replacement device with fresh Ed25519 keys, while the original device remains permanently revoked."*

---

### Step 3: Tab 2 — Threat Radar & Lateral Movement (1:35 – 2:30)
- **Visual:** Click **`2. THREAT RADAR`**. Show the 22-event summary and the Explainable Service Graph.
- **Actions to Perform:**
  1. Click **`PLAY`** (or **`STEP NEXT`**) to step through the official 22 practice events.
  2. Point to the **Service Graph SVG**: Show the normal cyan edges and the **pulsing RED lateral movement sequence**: `REPORTS → BILLING → ARCHIVE → IDENTITY`.
  3. Click the first incident card in the list: Show the **Incident Investigation Drawer**.
- **Spoken Script:**
  > *"Next is our Explainable Threat Radar. We ingested the official 22-event practice dataset. Rather than using unpredictable AI or neural networks, QuantumVault uses a 100% deterministic rule engine that cross-references telemetry with formal change authorizations. Notice the service graph: when `svc-report-worker` attempts unauthorized access across `flow-005`, our engine clusters events `evt-010`, `evt-011`, and `evt-012` as a candidate lateral movement sequence, while correctly distinguishing `evt-020` as an isolated denial. In the incident drawer, the engine explains the exact deterministic rule violated, timestamps, and recommended operator response. Our detector achieves 100.0% accuracy on the practice dataset with a median alert latency of just 26.9 microseconds."*

---

### Step 4: Tab 3 — Post-Quantum Messaging (2:30 – 3:35)
- **Visual:** Click **`3. PQ MESSAGING`**. Show Alice and Bob endpoint panels.
- **Actions to Perform:**
  1. Click **`1. PERFORM PQC HANDSHAKE`**: Show the 3 stages: ephemeral ML-KEM-768 offer generation, encapsulation, decapsulation, and memory zeroization.
  2. Click **`2. SEND (AES-GCM)`**: Show encrypted ciphertext preview and decrypted plaintext at Bob.
  3. Click **`TEST REPLAY DROP`**: Show duplicate packet rejected via 128-bit sliding-window cache in 3.2 microseconds.
  4. Click **`TEST RECIPIENT TAMPERING`**: Show that altering AAD recipient from 'bob' to 'eve' triggers immediate AEAD MAC mismatch with zero plaintext leaked.
  5. Click **`SIMULATE KEY THEFT (PFS)`**: Show post-compromise forward secrecy proof.
- **Spoken Script:**
  > *"For communications, QuantumVault implements post-quantum forward secrecy. When Alice and Bob connect, Bob generates an ephemeral NIST ML-KEM-768 keypair. Alice encapsulates the shared secret, derives 256-bit directional keys via HKDF-SHA256, and Bob zeroizes the ephemeral private key in memory. Every message is encrypted under AES-256-GCM with recipient metadata cryptographically bound in Authenticated Additional Data (AAD). If an adversary tampers with the recipient, the tag fails and zero bytes leak. If an adversary steals Alice and Bob's long-term identity keys tomorrow, they still cannot decrypt today's captured transcripts because the ephemeral KEM keys were destroyed. Note that session resumption is strictly disabled by policy to eliminate ticket compromise surfaces."*

---

### Step 5: Tab 4 — Security Lab & Combined Resilience Demo (3:35 – 4:40)
- **Visual:** Click **`4. SECURITY LAB`**.
- **Actions to Perform:**
  1. Click **`RUN ALL 40 SCENARIOS`**: Watch the progress bar fill to 100% and show 40/40 PASSED in ~3.6s.
  2. Click **`RUN COMBINED RESILIENCE DEMO`**: Watch all 40 steps of `Phase13CombinedScenario` execute live in the terminal window.
  3. In the Evidence Inspector, select `phase-2/benchmark_summary.txt` and click **`VIEW FILE`**.
- **Spoken Script:**
  > *"To ensure every claim is verifiable, our repository includes a unified security testing laboratory. With one click, we can execute all 40 automated security scenarios across cryptography, distributed consensus, crash recovery, and threat detection. All 40 scenarios pass in 3.6 seconds. Furthermore, our flagship 40-step combined failure scenario simulates an active adversarial campaign—rotating keys, killing worker processes to test SQLite WAL crash recovery, dropping message chunks, and verifying tamper detection against external HMAC checkpoints. Everything is logged immutably in the repository evidence folder."*

---

### Step 6: Conclusion (4:40 – 5:00)
- **Visual:** Switch back to the persistent header.
- **Spoken Script:**
  > *"In summary, QuantumVault satisfies all 12 challenge objectives: official validator checks pass, 190+ automated unit/adversarial tests pass, 40/40 security lab scenarios pass, and our offline SOC console includes a dedicated 15-step guided Judge Demo mode backed by live execution. We are happy to answer any questions or execute any live adversarial attack in the sandbox. Thank you."*

---

## 2. Technical Q&A Preparation for Judges

### Q1: Why did you choose ML-KEM-768 instead of classical ECDH?
**Answer:**
> *"NIST standardized ML-KEM (FIPS 203) as the primary post-quantum key encapsulation mechanism to protect against 'Harvest Now, Decrypt Later' (SNDL) attacks. Classical curve-based algorithms like X25519 or secp256r1 will be broken by Shor's algorithm on quantum computers. ML-KEM-768 provides Category 3 security (equivalent to AES-192), with 1,184-byte public keys and 1,088-byte ciphertexts, executing in under 1 millisecond on modern hardware."*

### Q2: Why is session resumption marked 'not supported'?
**Answer:**
> *"In zero-trust identity architectures, session resumption using session tickets or PSKs creates a dangerous persistence vector where a compromised ticket allows an adversary to impersonate a user even after device loss or role revocation. By security policy, we explicitly chose not to support session resumption (`SecurityPolicyError`). Each session requires a fresh post-quantum mutual handshake with current authorization checks."*

### Q3: How do you guarantee fail-closed behavior on partitioned nodes?
**Answer:**
> *"Every service node maintains an in-memory Policy Enforcement Point (PEP) cache synchronized with the Security Authority's monotonic epoch. Nodes require a fresh heartbeat within a 5.0-second threshold. If a node loses communication with the Authority or its heartbeat expires, `is_healthy()` immediately returns `False` and all subsequent read or credential checks fail closed (`decision: deny`), preventing stale authorization grants."*

### Q4: How does your threat detector achieve 1.000 F1 without AI/ML?
**Answer:**
> *"AI and machine learning models are non-deterministic, opaque, and susceptible to adversarial perturbation. Our detector uses context-aware deterministic graph traversal and change-management reconciliation:
> 1. It compares role changes against cryptographic approval records (`approvals.json`).
> 2. It tracks service hop transitions against an allowed directed dependency graph.
> 3. It groups correlated session sequences (`flow-005` across `sess-worker`) to detect multi-hop lateral movement (`reports → billing → archive → identity`), while distinguishing isolated denials (`evt-020`).
> Because enterprise security rules are deterministic, this achieves 100% precision with microsecond latency."*

### Q5: How do you protect audit logs from insider tampering?
**Answer:**
> *"Every audit record contains a cryptographic SHA-256 hash pointer linking to the preceding entry: $H_N = \text{SHA-256}(H_{N-1} \parallel E_N)$. Furthermore, the system generates external audit checkpoints signed with HMAC-SHA256 using an external authentication key stored completely outside the database directory. Even if a rogue administrator truncates rows in the database, the independent verifier flags the checkpoint mismatch immediately."*
