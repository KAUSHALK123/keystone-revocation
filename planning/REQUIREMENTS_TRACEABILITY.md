# QuantumVault — Requirements Traceability Matrix (RTM)
**Hackathon:** Yugaantar DevForge | **Track:** Track 4: "Trust, but verify"  
**Document Status:** Approved Architectural Planning (Phase-U)

---

## 1. Traceability Methodology

Every architectural feature, database entity, and test case in QuantumVault directly maps to an authoritative organizer requirement from one of three sources:
1. **[AC-v1]:** Official Adapter Contract v1 (`docs/adapter-v1.md`).
2. **[OBJ-1..12]:** The 12 Core Challenge Objectives (`templates/evidence-sheet.md` and Rentry problem statement).
3. **[EVAL-1..6]:** Stage 1 Automated Assessment and Rubric Categories (100 Points total).

Each requirement is classified as:
- **[REQ-MANDATORY]:** Binding competition requirement enforced by automated judging or contract.
- **[DEC-ARCHITECTURAL]:** Verified design decision chosen to satisfy requirements robustly.
- **[ENH-OPTIONAL]:** Secondary enhancement to be implemented only after all core requirements pass.

---

## 2. Comprehensive Requirements Traceability Matrix

| Req ID | Source Reference | Organizer Requirement Summary | QuantumVault Module | Architectural Implementation Decision | Verification & Test Mechanism | Phase-B Milestone |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **REQ-AC-01** | `docs/adapter-v1.md` §Process | Single entrypoint at repo root (`track4_service.py`), new process per operation, stdin/stdout JSON streaming. | `track4_service.py`, `Core Engine` | Standalone Python script reading `sys.stdin` to EOF, invoking shared `dispatch()`, emitting single JSON line, exit 0. | `python validate.py --entry track4_service.py`, regression suite `test_validate.py`. | **Milestone 1** |
| **REQ-AC-02** | `docs/adapter-v1.md` §Runtime | Read-only container root, write state to `TRACK4_STATE_DIR` or OS temp directory, max 64 KiB buffer. | `Persistence Layer` | SQLite DB in WAL mode located dynamically via `os.environ.get("TRACK4_STATE_DIR")` or `tempfile.gettempdir()`. | Buffer size verification, directory override tests. | **Milestone 1** |
| **REQ-AC-03** | `docs/adapter-v1.md` §Setup | Operation `setup`: ingest `owners`, `contents`, `disabled`, and sensitive `key_material`. Return `{"ready": true}` without leaking secrets. | `Vault & IAM Engine` | Atomic wipe and transaction re-initialization; stores key material internally; filters output streams. | Local validator Step 1 & 10; leak detection check Step 12. | **Milestone 1** |
| **REQ-AC-04** | `docs/adapter-v1.md` §Read | Operation `read`: for authorized owner return `{"decision":"allow","body":"..."}`; for denied return `{"decision":"deny"}` without body; log `request_id`. | `Authorization Engine` | Strict policy check: `actor not in disabled AND owners[asset] == actor`. Immutable record written to `audit_events`. | Local validator Steps 2, 3, 4, 6, 8, 9, 11. | **Milestone 1** |
| **REQ-AC-05** | `docs/adapter-v1.md` §Revoke | Operation `revoke`: revoke actor access permanently, persist across processes, keep peers unaffected. | `Revocation Engine` | Insert actor into `revocations` table; commit transaction before acknowledging; peer state untouched. | Local validator Step 5, 8, 9. | **Milestone 1** |
| **REQ-AC-06** | `docs/adapter-v1.md` §Audit | Operation `audit`: look up previous `request_id` and return recorded `decision`. | `Audit Engine` | Indexed query on `audit_events(request_id)`. Returns exact historic decision regardless of subsequent state changes. | Local validator Step 7. | **Milestone 1** |
| **REQ-AC-07** | `docs/adapter-v1.md` §ProtectedRead | Operation `protected_read`: encapsulate with raw Base64 ML-KEM-768 public key; return Base64 `ciphertext` & hex HMAC-SHA-256 `proof`. | `PQC KEM Engine` | Decodes Base64 PK; calls `pqcrypto.kem.ml_kem_768.encaps()`; derives HMAC-SHA-256 over `challenge + stored_body`. | Dedicated post-quantum round-trip test client; secret zeroization check. | **Milestone 2** |
| **REQ-AC-08** | `docs/adapter-v1.md` §ThreatModel | Root-level `threat-model.json` schema recognition (`{"asset":"protected-resource","boundary":"identity-check"}`). | Repository Root | Root-level static JSON descriptor matching exact organizer schema. | File existence and JSON validation test. | **Milestone 1** |
| **REQ-OBJ-01** | `Goal 1: Key rotation` | Authorized transfers continue; new requests reject old keys after cutoff; record version IDs and activation times. | `Key Lifecycle Manager` | Dual-key versioning state machine (Active V2, Grace V1, Retired). Grace cutoff strictly enforced. | Automated rotation fault-injection test; transfer continuity check. | **Milestone 3** |
| **REQ-OBJ-02** | `Goal 2: Revocation across nodes` | All distributed nodes reject revoked credentials; measure propagation time; safe device re-enrollment. | `Multi-Node Sync Engine` | Raft/Gossip mock node sync with monotonic version vectors; owner re-enrollment with new device ID. | Multi-node test harness; propagation delay timer (ms). | **Milestone 3** |
| **REQ-OBJ-03** | `Goal 3: Crash recovery` | Service recovers consistent state after interrupted rotation or crash; revoked credentials stay revoked; committed data remains safe. | `Transactional Persistence` | SQLite WAL mode with synchronous=FULL; atomic transition journaling; uncommitted state rolled back. | Process kill (-9) simulation during key commit; state audit upon restart. | **Milestone 2** |
| **REQ-OBJ-04** | `Goal 4: Backup integrity` | Recovery detects damaged or manipulated backups; rejects outdated snapshots restoring revoked credentials. | `Backup & Recovery Engine` | AES-256-GCM encrypted backups with HMAC-SHA-256 manifests and anti-rollback monotonic sequence counter. | Tampered backup injection test; stale backup restoration rejection test. | **Milestone 4** |
| **REQ-OBJ-05** | `Goal 5: Log integrity` | Audit log immutability; resist injection, truncation, deletion, or actor manipulation; verifiable key-event log. | `Tamper-Evident Logger` | Cryptographic hash-chaining (SHA-256 Merkle/block chain) with RFC 5424 structured parameter sanitization. | Log alteration detection test; log injection fuzzing test. | **Milestone 4** |
| **REQ-OBJ-06** | `Goal 6: Routine vs suspicious` | Distinguish approved changes from rogue privilege escalation; report F1, precision, recall, and median time to alert on labelled logs. | `Deterministic Threat Detector` | Deterministic approval correlation against `approvals.json` (actor, role, time window, scope); zero ML. | Benchmark execution against `practice/events.csv`; confusion matrix output. | **Milestone 5** |
| **REQ-OBJ-07** | `Goal 7: Lateral movement` | Flag abnormal cross-service hops even with valid credentials; correlate actor, session, and flow; distinguish denied from allowed. | `Service Graph Engine` | Directed service relationship graph; baseline allowed service edges; sequence anomaly detector for denied hops. | Detection of `flow-005` (`reports`->`billing`->`archive`->`identity`). | **Milestone 5** |
| **REQ-OBJ-08** | `Goal 8: Clock differences` | Handle out-of-order events and clock drift; calculate corrected time; flag temporal uncertainty windows. | `Telemetry Ingestion Pipeline` | Dual-timestamp architecture: `corrected_time = event_time - offset`; preserves received time; uncertainty flag if \|delta\| < jitter. | Ingestion test of `evt-013`/`014` and `evt-015` (+2000 ms). | **Milestone 5** |
| **REQ-OBJ-09** | `Goal 9: Replay & recipient binding` | E2EE messages bound to recipient identity; reject replays, duplicates, and manipulated recipient headers. | `Secure Messaging Engine` | AEAD envelope binding recipient public key fingerprint and monotonic message sequence number to AAD. | Replayed message rejection test; recipient tampering test. | **Milestone 6** |
| **REQ-OBJ-10** | `Goal 10: Forward secrecy` | Compromise of long-term identity keys does not compromise past session contents; ephemeral key lifecycle. | `PQC Session Engine` | Ephemeral ML-KEM-768 keypair per session/message; HKDF key derivation; in-memory secret zeroization. | Post-session identity key leak simulation proving past message confidentiality. | **Milestone 6** |
| **REQ-OBJ-11** | `Goal 11: Loss & reordering` | Reassemble segmented messages over lossy/reordered transport; discard corrupt chunks; report delivery failures. | `Message Transport Protocol` | Chunked framing with index, total count, chunk digest, and whole-message HMAC-SHA-256. | Packet drop and packet swap simulation in test laboratory. | **Milestone 6** |
| **REQ-OBJ-12** | `Goal 12: Session resumption` | Resumed sessions bound to authenticated peer; prevent session hijacking via copied token; fresh policy check. | `Session Manager` | Cryptographically signed resumption tokens containing peer key binding and epoch; fresh revocation verification. | Session token theft simulation; revoked session resumption denial test. | **Milestone 6** |

---

## 3. Rubric & Evaluation Traceability

| Rubric Category | Marks | Addressed By QuantumVault |
| :--- | :--- | :--- |
| **Security Correctness** | 25 | Standardized ML-KEM-768, HMAC-SHA-256, Zero-Knowledge on denial, verified key encapsulation. |
| **Live Security Assessment** | 25 | Active defense engine detects and mitigates attacks in real time, recovering up to 50% of any deductions. |
| **Functionality & Reliability** | 20 | Clean operation (5 pts), immediate revocation (5 pts), crash recovery (5 pts), verifiable outcomes (5 pts). |
| **Threat Model & Honesty** | 10 | Comprehensive two-page brief threat model, explicit acknowledgment of offline limitations and remaining risks. |
| **Performance & Overhead** | 10 | Sub-10ms adapter execution, lightweight SQLite WAL persistence, < 64 KiB stream footprint. |
| **Usability & Documentation** | 10 | Clean-machine setup instructions, single command test execution, rich operator and user interfaces. |
| **Total Marks** | **100** | **Targeting maximum score in Stage 1 to guarantee advancement to Stage 2 Desk Review.** |
