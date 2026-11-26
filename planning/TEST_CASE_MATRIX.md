# QuantumVault — Test Case & Automated Verification Matrix
**Hackathon:** Yugaantar DevForge | **Track:** Track 4: "Trust, but verify"  
**Document Status:** Approved Architectural Planning (Phase-U)

---

## 1. Testing Philosophy & Multi-Tier Verification Strategy

To guarantee that QuantumVault survives automated evaluation and live adversarial assessment, testing is structured into five rigorous tiers:
1. **Tier 1 — Official Adapter Conformance Tests:** Execution of the official organizer `validate.py` harness and `test_validate.py` regression suite.
2. **Tier 2 — Post-Quantum Cryptographic Interoperability Tests:** Standalone mathematical and byte-level verification of ML-KEM-768 key encapsulation and HMAC-SHA-256 proofs.
3. **Tier 3 — The 12 Core Challenge Objectives Tests:** Granular automated unit and integration tests mapped 1-to-1 to each official track objective.
4. **Tier 4 — Fault Injection & Combined Stress Tests:** Simulated host crashes, corrupted backups, network partitions, and adversarial tampering.
5. **Tier 5 — Telemetry Detection Benchmark:** Statistical evaluation of the threat detector against `practice/events.csv` to verify 100% precision, recall, and zero false alerts.

---

## 2. Tier 1: Official Adapter Conformance Tests

| Test ID | Test Category | Target Check | Input Conditions | Expected Result / Assertion | Pass Criteria |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-T1-01** | Setup | `clean setup` | `op="setup"` with owners, contents, disabled, marker. | Response `{"ready": true}`, exit 0, state initialized in temp dir. | PASS |
| **TC-T1-02** | Read (Auth) | `owner before device loss` | `op="read"`, valid owner, target asset, fresh request ID. | Response `{"decision": "allow", "body": "<exact_body>"}`, exit 0. | PASS |
| **TC-T1-03** | Read (Auth Peer)| `peer before device loss` | `op="read"`, valid peer, peer asset, fresh request ID. | Response `{"decision": "allow", "body": "<peer_body>"}`, exit 0. | PASS |
| **TC-T1-04** | Read (Denied)| `wrong owner` | `op="read"`, actor attempting to access peer's asset. | Response `{"decision": "deny"}`, zero body disclosure, exit 0. | PASS |
| **TC-T1-05** | Revocation | `revoke lost-device owner`| `op="revoke"`, target actor. | Response `{}`, actor added to disabled table, exit 0. | PASS |
| **TC-T1-06** | Read (Revoked)| `owner after revocation` | `op="read"`, revoked actor attempting to read own asset. | Response `{"decision": "deny"}`, zero body disclosure, exit 0. | PASS |
| **TC-T1-07** | Audit | `audit revoked read` | `op="audit"`, request ID from TC-T1-06. | Response `{"request_id": "<id>", "decision": "deny"}`, exit 0. | PASS |
| **TC-T1-08** | Read (Peer) | `unaffected peer` | `op="read"`, unaffected peer accessing own asset. | Response `{"decision": "allow", "body": "<peer_body>"}`, exit 0. | PASS |
| **TC-T1-09** | Persistence | `revocation persists across processes` | New process invoked; `op="read"` with revoked actor. | Response `{"decision": "deny"}` persisted from SQLite disk state. | PASS |
| **TC-T1-10** | Setup (Rerun)| `fresh rerun setup` | `op="setup"` in a completely fresh second temporary directory. | Response `{"ready": true}`, clean independent state, exit 0. | PASS |
| **TC-T1-11** | Read (Rerun) | `fresh rerun owner` | `op="read"` with actor in new directory. | Response `{"decision": "allow", "body": "<body_1>"}`; proves isolation. | PASS |
| **TC-T1-12** | Secret Leak | `fake key stays out of output` | Complete run inspection across all stdout/stderr streams. | Synthetic `key_material` token never appears in any output. | PASS |

---

## 3. Tier 2: Post-Quantum Cryptographic Tests

| Test ID | Test Category | Target Feature | Input Conditions | Expected Result / Assertion |
| :--- | :--- | :--- | :--- | :--- |
| **TC-T2-01** | PQC KEM | ML-KEM-768 Encapsulation | 1184-byte valid Base64 public key. | Ciphertext is 1088 bytes; shared secret is 32 bytes; no exceptions. |
| **TC-T2-02** | PQC KEM | Public Key Validation | Public key with invalid length (e.g. 500 bytes or 1200 bytes). | Rejects with `ValueError` or clean deny; zero unhandled crashes. |
| **TC-T2-03** | PQC KEM | Decapsulation Round-Trip | Generate `(pk, sk)`; encapsulate `(ct, ss_client)`; decapsulate `ss_server`. | `ss_client == ss_server` (Bit-for-bit exact agreement). |
| **TC-T2-04** | HMAC Proof | Challenge-Body Concatenation | Challenge `"ch123"`, Body `"data456"`, 32-byte secret. | Payload is UTF-8 `"ch123data456"`; proof matches expected hex HMAC. |
| **TC-T2-05** | Protected Read | Full Adapter Round-Trip | Valid owner, asset, challenge, Base64 PK to `protected_read`. | Emits JSON with `ciphertext` (Base64) and `proof` (Hex); exit 0. |
| **TC-T2-06** | Protected Read | Denied Access Protection | Revoked or wrong owner to `protected_read`. | Emits `{"decision": "deny"}`; omits `ciphertext` and `proof`. |

---

## 4. Tier 3: The 12 Core Challenge Objectives Tests

| Test ID | Objective | Test Description | Execution Command / Script | Expected Assertion |
| :--- | :--- | :--- | :--- | :--- |
| **TC-OBJ-01** | Goal 1: Key rotation | In-flight transfer continues under V1; new requests use V2; cutoff enforced. | `pytest tests/test_objectives.py::test_key_rotation` | Active transfers succeed; requests after cutoff with V1 rejected. |
| **TC-OBJ-02** | Goal 2: Revocation nodes | Revoke actor on Authority; verify Nodes A, B, C enforce denial; measure latency. | `pytest tests/test_objectives.py::test_revocation_propagation` | All nodes report deny; propagation time $\le 25\text{ ms}$; peer access intact. |
| **TC-OBJ-03** | Goal 3: Crash recovery | Terminate process mid-rotation; restart service; verify state consistency. | `pytest tests/test_objectives.py::test_crash_recovery` | Revocations stay revoked; committed keys available; clean WAL recovery. |
| **TC-OBJ-04** | Goal 4: Backup integrity | Inject corrupted bytes and forged checksum; attempt restore; attempt stale epoch. | `pytest tests/test_objectives.py::test_backup_integrity` | Damaged backup rejected; stale epoch rejected; valid backup restores 100%. |
| **TC-OBJ-05** | Goal 5: Log integrity | Modify intermediate row in log chain; verify detection; test CRLF injection. | `pytest tests/test_objectives.py::test_log_integrity` | Hash chain verification fails at tampered row; CRLF escaped to 1 JSON line. |
| **TC-OBJ-06** | Goal 6: Threat detection | Ingest `practice/events.csv`; compare against `practice/labels.csv`. | `pytest tests/test_objectives.py::test_practice_benchmark` | Precision = 1.0, Recall = 1.0, F1 = 1.0; 0 false alerts on benign events. |
| **TC-OBJ-07** | Goal 7: Lateral movement | Ingest `flow-005` hops; verify detection of abnormal service path. | `pytest tests/test_objectives.py::test_lateral_movement` | Flags candidate lateral sequence; reports requests denied; no false breach. |
| **TC-OBJ-08** | Goal 8: Clock differences | Ingest `evt-013`/`014` (reordered) and `evt-015` (+2000ms skew). | `pytest tests/test_objectives.py::test_clock_skew` | Corrected time calculated; delay = 200ms; chronological order restored. |
| **TC-OBJ-09** | Goal 9: Replay & binding | Replay encrypted packet; modify recipient ID in header. | `pytest tests/test_objectives.py::test_replay_binding` | Duplicate packet rejected; tampered recipient fails AEAD authentication. |
| **TC-OBJ-10** | Goal 10: Forward secrecy | Record session traffic; leak long-term identity private key; attempt decrypt. | `pytest tests/test_objectives.py::test_forward_secrecy` | Decryption fails; past ephemeral session secrets unrecoverable. |
| **TC-OBJ-11** | Goal 11: Loss & reordering | Drop chunk 3 of 5; reorder chunks 1,4,2,5,3; test reassembly. | `pytest tests/test_objectives.py::test_loss_reordering` | Dropped chunk fails cleanly; reordered chunks reassemble to exact original. |
| **TC-OBJ-12** | Goal 12: Session resumption | Resumption token replayed by unauthorized actor; resume after revocation. | `pytest tests/test_objectives.py::test_session_resumption` | Token bound to peer key; revoked identity fails fresh policy check. |

---

## 5. Tier 4: Fault Injection & Security Stress Tests

| Test ID | Stress Scenario | Fault Injected | Expected System Reaction |
| :--- | :--- | :--- | :--- |
| **TC-T4-01** | Process Kill (`SIGKILL`) | Kill process while executing `read` transaction. | Next invocation opens SQLite WAL cleanly; no deadlocks or corruption. |
| **TC-T4-02** | State File Locking | Create exclusive lock on database file. | `busy_timeout` backoff engages; clean error without unhandled traceback. |
| **TC-T4-03** | Max Output Flooding | Service attempts to return 100 KiB body. | Buffer cap triggers format error; process killed before violating 64 KiB rule. |
| **TC-T4-04** | Disconnected Node Partition | Sever network socket to Node C during active revocation. | Node C heartbeat times out; fails closed for protected reads. |
| **TC-T4-05** | Corrupt Memory Scrubbing | Inspect heap post-protected read. | Shared secret buffer overwritten with zeroes. |

---

## 6. Tier 5: Combined Hackathon Stress Scenario (The "Grand Demo")

A single integrated test script executing the 11-step combined failure scenario:
1. Alex transfers file under Key V1.
2. Administrator triggers Key Rotation to V2.
3. Alex's device is reported stolen.
4. Node C loses connectivity.
5. Node B crashes during rotation.
6. Thief attempts reading file with stolen device.
7. Outdated backup is presented to recover system.
8. Node B restarts.
9. Node C reconnects and synchronizes.
10. Alex enrolls replacement device.
11. Blair accesses unaffected resource.

**Expected Assertion:**
- Stolen device is rejected across all nodes.
- Disconnected Node C fails closed.
- Node B recovers consistent V2 state.
- Stale backup is rejected by anti-rollback counter.
- Node C catches up to Epoch 101.
- Alex recovers access via Device 2.
- Blair experiences zero downtime.
- Test outputs complete telemetry proof log.
