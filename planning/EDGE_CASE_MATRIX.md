# QuantumVault — Edge-Case & Failure Mode Matrix
**Hackathon:** Yugaantar DevForge | **Track:** Track 4: "Trust, but verify"  
**Document Status:** Approved Architectural Planning (Phase-U)

---

## 1. Overview

This document provides an exhaustive, multi-domain edge-case matrix covering 55 distinct failure modes across Identity & Access, Cryptographic Key Management, Backup & Persistence, Audit & Threat Detection, and Secure Communication.

---

## 2. Comprehensive Edge-Case Matrix

### Domain 1: Identity, Devices & Authorization

| Scenario ID | Edge-Case Scenario | Expected Secure Behavior | Proposed Implementation | Automated Test Procedure | Residual Risk |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **EC-ID-01** | Wrong user accesses protected resource. | Deny access; return `{"decision":"deny"}`; disclose zero bytes of body. | Check `owners.get(asset) == actor`. Return deny if mismatch. | Local validator Step 4 (`wrong owner`). | Zero risk. |
| **EC-ID-02** | Unknown actor or non-existent asset ID. | Deny access cleanly; no crash or stack trace leakage. | Dict `.get()` or parameterized query returning empty; defaults to deny. | Submit random UUID actor/asset; assert exit 0 & decision deny. | Zero risk. |
| **EC-ID-03** | Disabled / revoked actor attempts access. | Deny access; persist denial; log audit entry. | Check `actor in disabled_table`. Enforce immediate deny. | Local validator Step 6 (`owner after revocation`). | Zero risk. |
| **EC-ID-04** | Duplicate device ID registration attempt. | Reject duplicate; maintain original binding; log warning. | `UNIQUE(device_id)` constraint in SQLite; abort with conflict error. | Attempt registering existing `device-001` with new PK; assert 409 Conflict. | Stale device lookup if DB locked. |
| **EC-ID-05** | Stolen device credentials used after report. | Immediately deny access across all nodes. | Device ID added to `revocations`; checked on every PEP evaluation. | Report device lost; invoke read with device token; assert deny. | Offline cache extraction on unencrypted local hardware. |
| **EC-ID-06** | Unauthorized account recovery request. | Reject recovery; require valid secondary proof; alert operator. | Recovery requires multi-factor secret or master admin authorization. | Submit recovery with invalid token; assert 403 Forbidden. | Weak secondary recovery secrets if user chosen. |
| **EC-ID-07** | Loss of all registered devices for user. | Account locked to read-only; admin-assisted identity re-verification required. | Emergency administrative re-enrollment workflow. | Revoke all devices for actor; verify self-service reads fail; admin unblocks. | Operational delay while awaiting manual admin review. |
| **EC-ID-08** | Stolen / copied session token presented. | Deny if bound to different client IP/TLS fingerprint or revoked. | Cryptographically sign session token with peer device public key binding. | Replay session token from secondary IP/device; assert rejected. | Local proxy MITM if client TLS cert unpinned. |
| **EC-ID-09** | Expired access authorization (time-bounded lease). | Deny read immediately upon lease expiration. | Check `CURRENT_TIMESTAMP < valid_until_utc`. | Mock system clock past expiry; submit read; assert deny. | Clock drift on un-synchronized local client. |
| **EC-ID-10** | Unauthorized role change / privilege escalation. | Deny administrative action; flag security alert (`unexpected_role_change`). | Cross-reference requested role against `approvals.json`; require approval ID. | Replay `evt-008` (Blair becoming operator); assert detector flags alert. | Zero risk. |
| **EC-ID-11** | Rogue administrator injects fake approval. | Reject approval if administrative signing key does not verify. | Verify digital signature on change approval record. | Inject unsigned approval in DB; attempt role grant; assert rejected. | Compromised root admin signing key. |
| **EC-ID-12** | Expired or incorrectly scoped approval used. | Reject role change; do not activate permissions. | Validate `current_time < valid_until` and `target_service in scope`. | Attempt role change at `09:08:00Z` using `change-100` (expired `09:07:00Z`); assert denied. | Clock skew between admin console and service. |
| **EC-ID-13** | Simultaneous permission changes for same actor. | Serializable ACID execution; last committed transaction prevails deterministically. | SQLite `BEGIN IMMEDIATE TRANSACTION` ensures serialized execution. | Spawn 10 concurrent threads revoking/granting role; verify DB consistency. | Transient `SQLITE_BUSY` handled via exponential backoff. |

---

### Domain 2: Cryptographic Key Management

| Scenario ID | Edge-Case Scenario | Expected Secure Behavior | Proposed Implementation | Automated Test Procedure | Residual Risk |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **EC-KM-01** | Two simultaneous key rotations initiated. | Exactly one rotation succeeds; second receives conflict status. | Atomic CAS on `app_state.active_key_version`. | Concurrently trigger rotation V1->V2 and V1->V3; assert exactly one active. | Minimal. |
| **EC-KM-02** | Rotation occurs during active file transfer. | Active transfer completes under grace period; new transfers use new key. | Grace period window allows V1 for in-flight requests until cutoff. | Start large transfer under V1; trigger V2 rotation; verify transfer finishes. | Long-running transfers exceeding grace window. |
| **EC-KM-03** | Revocation initiated during active grace period. | Revocation overrides grace period immediately; transfer aborted. | PEP checks `is_revoked(actor)` BEFORE checking key version validity. | Trigger revocation mid-grace period; assert subsequent block read denied. | In-flight bytes already in OS network buffer. |
| **EC-KM-04** | Old key used after cutoff timestamp. | Request unconditionally rejected with `key_retired`. | Check `current_time > cutoff_at`; reject retired key. | Submit read request signed with V1 key after cutoff; assert deny. | Clock drift between nodes. |
| **EC-KM-05** | Service node operates with stale key version. | Stale node fails closed for sensitive operations until synced. | Node checks cluster epoch heartbeat before decrypting. | Disconnect Node C; rotate key to V2; submit V2 read to Node C; assert fail-closed. | Temporary availability reduction during partition. |
| **EC-KM-06** | Invalid / truncated ML-KEM-768 public key. | Reject cleanly; return `{"decision":"deny"}` or format error; no crash. | Assert `len(pk_bytes) == 1184` before invoking `encaps()`. | Submit 1000-byte Base64 key to `protected_read`; assert clean deny. | Zero risk. |
| **EC-KM-07** | Malformed Base64 string in `public_key`. | Return error/deny cleanly without unhandled exception. | Wrap `base64.b64decode(validate=True)` in try-except block. | Pass `"!@#$%^&*"` as public key; assert exit code 0 or 1, no unhandled exit 2. | Zero risk. |
| **EC-KM-08** | Nonce reuse in symmetric encryption. | Never reuse nonces; reject duplicate nonces at receiver. | 96-bit CSPRNG nonce combined with 64-bit monotonic sequence counter. | Generate 100,000 nonces in test harness; verify zero collisions. | Hardware RNG failure (mitigated by system CSPRNG). |
| **EC-KM-09** | Exposure of long-term identity key. | Past completed sessions remain unreadable (Forward Secrecy). | Ephemeral ML-KEM shared secrets; HKDF session keys erased from RAM. | Decrypt recorded past session ciphertext with exposed long-term key; assert failure. | Un-zeroized RAM in managed language GC. |
| **EC-KM-10** | Missing historical DEK during file retrieval. | Return clean error; log key retrieval failure; do not crash. | Look up DEK in vault; return `key_unavailable` if archived. | Delete DEK from test DB; attempt read; assert clean error. | Permanent data loss if DEK backup missing. |
| **EC-KM-11** | Crash immediately before key rotation commit. | System reboots with previous key active; no state corruption. | SQLite transaction rolls back uncommitted key activation. | Terminate process (`kill -9`) prior to commit; reboot; assert V1 active. | Zero risk. |
| **EC-KM-12** | Crash immediately after key rotation commit. | System reboots with new key active; old key in grace/retired. | SQLite WAL commit record replayed upon reboot. | Terminate process immediately post-commit; reboot; assert V2 active. | Zero risk. |

---

### Domain 3: Backup & Persistence

| Scenario ID | Edge-Case Scenario | Expected Secure Behavior | Proposed Implementation | Automated Test Procedure | Residual Risk |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **EC-BP-01** | Corrupted backup file (bit flips in archive). | Detection fails authentication tag; restoration aborted. | AES-256-GCM authentication tag verification over entire archive. | Flip 1 byte in backup archive; invoke restore; assert `TagMismatchError`. | Zero risk. |
| **EC-BP-02** | Modified backup and forged checksum. | Restoration rejected because HMAC/signature key is unknown to attacker. | Backup protected by secret HMAC key or private signing key. | Modify backup and recalculate plain SHA-256; invoke restore; assert rejected. | Leaked backup authentication key. |
| **EC-BP-03** | Rollback attack using old, valid backup (stale epoch). | Restoration rejected; prevents resurrection of revoked credentials. | Monotonic cluster epoch verified against trusted hardware/checkpoint. | Restore valid backup from Epoch 90 when current is Epoch 100; assert rejected. | Lost or corrupted anti-rollback counter. |
| **EC-BP-04** | Missing backup decryption key during disaster recovery. | Abort cleanly; report clear diagnostic; prevent partial writes. | Verify key availability before reading archive stream. | Invoke restore without providing key; assert clear error. | Inability to recover if key lost. |
| **EC-BP-05** | Backup contains revoked credentials. | Revocations re-applied or persistent blacklist enforced post-restore. | Anti-rollback epoch check prevents restoring state prior to revocations. | Attempt restoring pre-revocation backup; assert rejected. | Outdated local policy caches. |
| **EC-BP-06** | Process crash during backup creation. | Partial backup file deleted or ignored; active DB unaffected. | Write backup to `.tmp` file; atomic rename upon successful completion. | Terminate process mid-backup; assert `.tmp` discarded and DB intact. | Temporary disk space consumption. |
| **EC-BP-07** | Process crash during backup recovery. | Active database remains functional; incomplete restore rolled back. | Restore writes to staging DB; validates; atomically swaps files. | Terminate process mid-restore; reboot; assert original DB untouched. | Zero risk. |
| **EC-BP-08** | Concurrent database writes from multiple processes. | Serialized execution without database locks or corruptions. | SQLite WAL mode with `busy_timeout = 5000ms`. | Spawn 20 parallel processes writing to DB; assert 0 deadlocks, 100% success. | High-concurrency write latency. |
| **EC-BP-09** | Unwritable state directory (filesystem permissions). | Catch OS error; report clean setup failure; exit code 2. | Try-except `OSError` during DB creation; emit clean diagnostic. | Run validator against read-only folder; assert exit code 2. | Configuration error in container. |
| **EC-BP-10** | State isolation across independent judging runs. | State from Run 1 does not bleed into Run 2. | Setup cleans tables or runs in fresh temporary directory. | Run validator twice with distinct temp directories; assert complete isolation. | Zero risk. |

---

### Domain 4: Audit & Threat Detection

| Scenario ID | Edge-Case Scenario | Expected Secure Behavior | Proposed Implementation | Automated Test Procedure | Residual Risk |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **EC-TD-01** | Log injection attempt via newline/CR in input. | Input escaped; single canonical JSON line written; no phantom log. | Strict JSON serialization via `json.dumps()`; escapes `\r`, `\n`. | Pass actor name `"user\n[AUDIT] allow admin"`; verify single log row. | Zero risk. |
| **EC-TD-02** | Actor field manipulation in telemetry. | Original authenticated actor preserved; spoofed client header ignored. | Actor extracted from authenticated session token, not client payload. | Submit request with header `X-Actor: admin`; verify log records true caller. | Stolen session token. |
| **EC-TD-03** | Duplicate request ID submitted. | Reject duplicate or audit distinct instances without overwriting history. | Unique constraint on `request_id` or sequential versioning. | Submit two reads with identical `req-001`; verify first decision unaltered. | Client retry collisions. |
| **EC-TD-04** | Malicious deletion of an intermediate audit row. | Verification detects break in cryptographic hash chain. | Each row stores `SHA256(prev_hash || row_data)`. | Delete row 5 from DB; run audit integrity check; assert verification fails at row 6. | Untracked if entire DB replaced without external checkpoint. |
| **EC-TD-05** | Truncation of recent audit events. | Verification detects discrepancy against external epoch checkpoint. | Store latest sequence counter in separate signed checkpoint file. | Delete last 5 rows of log; compare against checkpoint; assert truncation flagged. | Truncation before checkpoint written. |
| **EC-TD-06** | Rewriting entire audit chain with fake keys. | Verification detects signature mismatch against trusted public key. | Checkpoint digests signed by dedicated offline log integrity key. | Recalculate hash chain with attacker key; verify signature fails. | Leaked log signing key. |
| **EC-TD-07** | Approved administrator activity (`evt-003`-`005`). | Classified as benign (`approved_change`); no false positive alarm. | Correlate with `approvals.json` (subject, role, scope, time window). | Ingest `evt-003`-`005`; assert classified as approved change. | Complex multi-tier approvals. |
| **EC-TD-08** | Unauthorized role change (`evt-008`). | Flagged as critical alert (`unexpected_role_change`). | Missing approval in `approvals.json` triggers alert. | Ingest `evt-008`; assert alert emitted with event ID and actor. | Zero risk. |
| **EC-TD-09** | Lateral movement across services (`evt-010`-`012`). | Grouped into candidate lateral movement incident; not flagged as breach. | Directed service graph detects unauthorized edge traversal; notes `outcome: deny`. | Ingest `flow-005`; assert lateral movement candidate alert emitted. | Novel legitimate service paths. |
| **EC-TD-10** | Single isolated access denial (`evt-020`). | Classified as `isolated_denial`; does not trigger attack campaign alert. | Threshold rule: isolated denial without sequence is routine. | Ingest `evt-020`; assert classified as isolated denial, no campaign alert. | Low-and-slow brute force probes. |
| **EC-TD-11** | Out-of-order event delivery (`evt-013` vs `evt-014`). | Preserves both arrival order and logical event timeline. | Store both `received_time_utc` and `event_time_utc`. | Ingest `evt-014` then `evt-013`; assert correct chronological ordering. | Buffer memory limits during massive reordering. |
| **EC-TD-12** | Event with source clock offset (`evt-015`, +2000ms). | Calculates corrected time; confirms benign delivery delay (200ms). | `corrected_time = event_time - offset`. | Ingest `evt-015`; verify corrected time `09:06:01.000Z`, delay 200ms. | Unreported or variable clock jitter. |
| **EC-TD-13** | Duplicate telemetry event ingested. | Deduplicated via `event_id`; logged once; no double-counting. | Primary key constraint on `event_id`. | Ingest `evt-001` twice; assert DB contains exactly one record. | High ingestion volume overhead. |
| **EC-TD-14** | Ambiguous event ordering within clock uncertainty window. | Flagged as temporally ambiguous; does not invent false causal order. | Uncertainty window $\pm 500\text{ms}$; flag sequence as concurrent. | Ingest 2 events with \|$\Delta t$\| < clock uncertainty; assert flagged ambiguous. | Concurrency resolution in distributed consensus. |

---

### Domain 5: Secure Communication & Messaging

| Scenario ID | Edge-Case Scenario | Expected Secure Behavior | Proposed Implementation | Automated Test Procedure | Residual Risk |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **EC-CM-01** | Replayed encrypted message. | Reject duplicate; log replay attempt; drop payload. | Monotonic sequence number and Bloom filter / hash set of seen message IDs. | Re-transmit exact message ciphertext; assert rejected as duplicate. | Memory bounds on replay cache (mitigated by epoch sliding window). |
| **EC-CM-02** | Recipient metadata modified in transit. | Authentication tag verification fails; payload dropped. | Recipient ID included in AEAD Associated Authenticated Data (AAD). | Alter recipient from "Bob" to "Eve" in message header; assert decryption fails. | Zero risk. |
| **EC-CM-03** | Sender or session metadata modified in transit. | Authentication tag verification fails; payload dropped. | Sender ID and Session ID included in AEAD AAD. | Alter sender ID in ciphertext envelope; assert decryption fails. | Zero risk. |
| **EC-CM-04** | Corrupted ciphertext bits in transit. | Decryption fails GCM authentication check; no partial plaintext leaked. | Standard AES-256-GCM tag verification. | Flip single bit in ciphertext body; assert GCM tag error. | Zero risk. |
| **EC-CM-05** | Missing message chunk in segmented transfer. | Reassembly fails; timeout expires; chunk discarded; failure reported. | Chunks tracked via bitmask; timer expires after 10s if incomplete. | Drop chunk 3 of 5; verify receiver reports delivery failure and zero plaintext leaked. | Network packet drop in transit. |
| **EC-CM-06** | Reordered chunks in segmented transfer. | Chunks buffered in bounded memory; reassembled in correct index order. | Pre-allocated array indexed by `chunk_index`. | Transmit chunks in order 4, 1, 3, 5, 2; verify complete reassembly. | Memory exhaustion if chunk count unbounded (mitigated by max 64 chunks). |
| **EC-CM-07** | Duplicate chunk received. | Duplicate chunk silently discarded; does not corrupt reassembly. | Track received chunk indices in bitmask. | Transmit chunk 2 twice; verify reassembled message is exact. | Minimal. |
| **EC-CM-08** | Interrupted transfer during chunked transmission. | Receiver cleans up buffer after timeout; reports delivery failure. | Incomplete transfer garbage collection timer. | Send 2 of 10 chunks; disconnect; verify buffer purged after 15s. | Temporary buffer allocation. |
| **EC-CM-09** | Recipient rotates public key while message is queued. | Message decryptable if recipient preserves grace key; else retry with V2. | Recipient maintains predecessor private key during active grace period. | Queue message for PK-V1; rotate to PK-V2; deliver message; assert success. | Expired grace window requiring sender re-encryption. |
| **EC-CM-10** | Sender revoked before queued message delivery. | Receiver checks sender revocation status upon delivery; rejects message. | Receiver performs live revocation check before exposing decrypted plaintext. | Revoke sender while message in transit; deliver message; assert receiver denies. | Stale revocation cache at receiver. |
| **EC-CM-11** | Session takeover attempt using copied session token. | Rejected; session bound to peer public key / TLS binding. | Mutual cryptographic authentication binding session to peer key. | Submit stolen session ID from unauthorized actor; assert rejected. | Endpoint private key compromise. |
| **EC-CM-12** | Excessively large message (> 10 MiB) submitted. | Rejected at framing layer before memory allocation; 413 Payload Too Large. | Max payload limit enforced at stream parser (e.g. 5 MiB cap). | Send 15 MiB payload to messaging endpoint; assert rejected with 413. | DoS attempt if streaming parser missing. |
| **EC-CM-13** | Long-term identity key exposed post-session. | Past session transcripts remain confidential (Forward Secrecy). | Ephemeral ML-KEM exchange; session secrets zeroized. | Compromise long-term key; attempt decrypting past recorded traffic; assert failure. | Memory dumping before process exit. |
