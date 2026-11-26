# QUANTUMVAULT — NEXT MODEL HANDOFF DOCUMENT
> Generated: 2026-11-27T00:32:00+05:30  
> Project: `D:\PROJECTS\keystone-revocation`  
> Branch: `feature/adversarial-eval`  
> Python: `C:\Python313\python.exe` (3.13.3, Windows)

---

## WHAT THIS PROJECT IS

**QuantumVault** — a Yugaantar DevForge Track 4 hackathon submission ("Key Identity Guard / Trust, but verify").  
Domain: Post-Quantum Cryptography (ML-KEM-768, ML-DSA-65) + Zero-Trust Identity & Access Control.

---

## WHAT HAS BEEN DONE (ALL PHASES)

### Phase 1 — Prior Sessions (Pre-Handoff Summary)
Several earlier sessions completed:
- Full adversarial test suites written under `/tests_eval/` and `/tests_round2/`
- Senior engineer fixes applied (clean-machine build, Python 3.11+ guard, pqcrypto pin, `from __future__ import annotations`)
- Push to `feature/adversarial-eval` branch
- Full desk review / judge simulation report written
- Compliance & AI/ML audit run (verdict: CLEAN, no AI components)
- Technical writer pass: documented every implemented feature with file:line evidence

### Phase 2 — Current Session (This Run)
**Goal**: Create `final_security_validation/` — the EXTREME INDEPENDENT VALIDATION directory with:
- 169 test cases across 14 security categories
- Empirical micro-benchmarks
- Rubric assessment (100-pt scoring)
- 5 JSON reports + 1 Markdown report (20 sections)

**Files Created (all inside `final_security_validation/`):**
| File | Status |
|------|--------|
| `README.md` | ✅ Complete |
| `mock_environment.py` | ✅ Complete — IsolatedTestEnvironment, SyntheticOrganization, make_security_event(), generate_unseen_telemetry() |
| `test_cases.py` | 🔧 In Progress — 168 tests registered (1 was deduped); **currently 115 PASS, 53 FAIL** |
| `challenge-u-to-break.py` | ✅ Wired correctly — imports `run_all_tests`, `CATEGORY_MAP`, runs benchmarks, produces all 5 reports |
| `reports/` | 📂 Exists, populated on each run |

---

## CURRENT STATE OF TEST RESULTS

**Last run result: 168 tests, 115 PASSED, 53 FAILED**

> NOTE: 169 tests were registered but 1 appears to have been deduplicated (TC-MSG-001 to 011 rewrite caused 1 test to vanish). Check registry count after fixes.

---

## EXACT REMAINING FAILURES (53 tests)

### Group A: `test_cases.py` still has OLD un-patched code  
The patch scripts ran and said "success" but the **file still contains the old source text** because Python `str.replace()` did NOT match (the file uses CRLF `\r\n` line endings while patches used `\n`). All the fixes below need to be applied directly with `edit_file` tool calls on exact matching lines.

#### TC-LOST-001 — `user['id']` KeyError
- **File**: `final_security_validation/test_cases.py` **line 127**
- **Fix**: Change `user['id']` → `user.get('actor_id')`

#### TC-LOST-004 — `owner_id=` → `asset_owner=`, `owner_access` → `owner_allowed`
- **File**: line ~192
- **Fix**:
  ```python
  # OLD:
  decision, rule = PolicyEngine.evaluate_access(actor="alice", asset="asset-synth-001", owner_id="alice", is_disabled=False)
  passed = (decision == "allow" and rule == "owner_access")
  # NEW:
  decision, rule = PolicyEngine.evaluate_access(actor="alice", asset="asset-synth-001", asset_owner="alice", is_disabled=False)
  passed = (decision == "allow" and rule == "owner_allowed")
  ```

#### TC-LOST-006 — `MessagingSession(sender_id=...)`
- **File**: line ~235
- **Fix**: Replace full function body:
  ```python
  hs = MessagingHandshake()
  offer = hs.generate_responder_offer("portal", "portal-dev", sk_resp)
  payload, k_send, k_recv = hs.initiate_session("alice", "phone-b", sk_init, offer, offer["ephemeral_kem_pk_b64"])
  passed = bool(k_send and k_recv and offer.get("session_id"))
  ```

#### TC-LOST-008 — `dm.is_device_revoked()` / `rev_info.get("status")`
- `DeviceManager` has NO `is_device_revoked` method.
- `revoke_device()` returns `None`.
- **Fix**:
  ```python
  dm.revoke_device(device_id="phone-b", reason="reported_stolen")
  dev = dm.get_device("phone-b")
  is_revoked = not dm.is_device_active("phone-b")
  passed = bool(dev and dev.get("status") == "revoked" and is_revoked)
  ```

#### TC-LOST-010 — `dm.authenticate_device_response()`
- No such method. Use: `dm.is_device_active("phone-b")` (should return False post-revoke).
- **Fix**: `auth_allowed = dm.is_device_active("phone-b")`; `passed = (auth_allowed is False)`

#### TC-LOST-014 — same as LOST-010 (two calls to `authenticate_device_response`)
- Fix both calls: `a1 = dm.is_device_active("phone-b ")` / `a2 = dm.is_device_active("Phone-B")`

#### TC-LOST-015 — `dm2.is_device_revoked("phone-b")`
- **Fix**: `is_rev_after_restart = not dm2.is_device_active("phone-b")`

#### TC-LOST-016, 017, 021 — `dm.get_device_status(...)`
- No such method.
- **Fix**:
  ```python
  phone_a_status = "active" if dm.is_device_active("phone-a") else "revoked"
  laptop_status = "active" if dm.is_device_active("laptop-a") else "revoked"
  dev_status = "active" if dm.is_device_active("phone-b") else "revoked"
  ```

#### TC-LOST-019 — `dm.is_device_revoked` + `dm.get_device_status`
- Fix both.

---

### Group B: KeyRotationManager API mismatches

**Root Cause**: `rotate_key()` signature is:
```python
def rotate_key(self, new_version_id: str, grace_seconds: float = 30.0, rewrap_assets: bool = True)
```
It does NOT accept a raw `new_key: bytes` as 2nd positional arg. All broken tests pass `b"N" * 32` there.

**Also**: `KeyRotationManager` has NO `get_version()` method. Use `mgr.key_repo.get_version()`.  
**Also**: DB column is `status` not `state`.

#### TC-ROT-001
- Fix: `v1_meta = mgr.key_repo.get_version("v1")` and `v1_meta["status"]`

#### TC-ROT-002
- Fix: Remove raw key arg `mgr.rotate_key("v2", new_key)` → `mgr.rotate_key("v2", grace_seconds=30.0)`
- Remove: `res["new_version"] == "v2"` → `res["active_version"] == "v2"`

#### TC-ROT-003, 004, 008, 011
- Remove `grace_period_seconds=0` → `grace_seconds=0.0`
- For TC-ROT-003 and TC-ROT-011: use `mgr.expire_cutoff("v1")` after rotation to immediately retire v1
- For TC-ROT-004: check `CryptoError` for "retired" or "expired"

#### TC-ROT-005 — `env.key_path.write_bytes(k2)` corrupts KEK
- **Remove that line entirely**. The rotate_key function generates its own random new key; don't overwrite with `b"Z"*32`

#### TC-ROT-006
- `mgr.get_active_version()` → `mgr.key_repo.get_active_version()`

#### TC-ROT-007 — `vault.rewrap_assets("v1","v1")`
- No such method on `ResourceVault`.
- **Fix**: use `KeyRotationManager.rotate_key()`:
  ```python
  conn = get_connection(env.db_path)
  mgr = KeyRotationManager(conn, load_vault_key(env.key_path))
  res = mgr.rotate_key("v2", grace_seconds=30.0, rewrap_assets=True)
  rewrapped = res["rewrapped_count"]
  conn.close()
  passed = (rewrapped >= 100)
  ```

#### TC-ROT-009 — SQLite schema: column `state` doesn't exist
- Fix: Use `status` in the INSERT:
  ```python
  conn.execute("INSERT INTO key_versions (version_id, encrypted_key_bytes, nonce, status) VALUES ('v-crash', X'00', X'00', 'active');")
  ```

#### TC-ROT-010
- Same issue: `mgr.rotate_key("v2a", b"A" * 32)` → `mgr.rotate_key("v2a", grace_seconds=30.0)`

---

### Group C: Detection (TC-TR-001, 003, 008, 009)

#### TC-TR-001, 003, 008 — `ApprovalRegistry.add_approval()` 
- Real method is `ApprovalRegistry.add(approval: ApprovalChange)` — takes ONE arg (the dataclass).
- **Fix**:
  ```python
  from quantumvault.detection.models import ApprovalChange
  approvals = ApprovalRegistry()
  approvals.add(ApprovalChange(
      approval_id="apr-bob-role-01",
      approved_by="bob",
      subject="bob",
      operation="grant_role",
      role="admin"
  ))
  ```

#### TC-TR-009 — `incident.title`
- `Incident` dataclass has NO `title` field. Use `incident.incident_type`.

---

### Group D: Audit (TC-AUD-002, 003, 004, 005, 006, 008, 011)

#### TC-AUD-002, 003, 005, 006, 011 — `no such table: audit_log`
- Real table is `audit_events`. All SQL queries need `FROM audit_events`.

#### TC-AUD-004 — `logger.get_latest_hash()`
- No such method. Use: `logger.repo.get_last_entry()["entry_hash"]`

#### TC-AUD-008 — field `"timestamp"` doesn't exist in audit schema
- Real field is `"event_time_utc"`. Fix the fields list check.

---

### Group E: Identity (TC-AUTH-002, 006)

#### TC-AUTH-002 — `dm.authenticate_device_response()`
- Fix: `auth_res = dm.is_device_active("dev-unknown")` → `passed = (auth_res is False)`

#### TC-AUTH-006 — `no such table: recovery_codes`
- Real table is `recovery_credentials`.
- Fix: `SELECT code_hash, salt FROM recovery_credentials WHERE actor_id='carol';`

---

### Group F: Messaging (TC-MSG-001 to 011)

The entire messaging block was rewritten in the last patch but the **patch did NOT actually take effect** (CRLF mismatch). The old code using `MessagingSession("alice","bob")` etc. is still in the file.

**The correct API is:**
```python
# MessagingSession constructor:
MessagingSession(session_id, local_actor_id, local_device_id, remote_actor_id, remote_device_id, k_send, k_recv)

# MessagingHandshake: must instantiate first
hs = MessagingHandshake()
offer = hs.generate_responder_offer("bob", "bob-dev", sk_bytes)
payload, k_send, k_recv = hs.initiate_session("alice", "alice-dev", sk_bytes, offer, offer["ephemeral_kem_pk_b64"])
k_recv_b, k_send_b = hs.complete_responder(offer, payload, payload["initiator_pqc_pk_b64"])

# MessagingSession send/receive:
pkg = session.send_message(b"plaintext")
plaintext = session.receive_message(pkg)

# ChunkedTransport:
chunks = transport.segment_payload("msg-id", payload_bytes)
ok, data, missing = transport.reassemble(chunks)  # returns tuple, not raises

# EncryptedOutbox:
outbox = EncryptedOutbox(conn, local_storage_key=kek)
```

---

### Group G: Concurrency (TC-RACE-003, 008)

#### TC-RACE-003
- Same as ROT issues: `mgr.rotate_key("v2", b"N"*32)` → `mgr.rotate_key("v2", grace_seconds=30.0)`

#### TC-RACE-008
- `dm.authenticate_device_response()` → `dm.is_device_active("phone-b")`

---

### Group H: Dashboard (TC-DASH-004)

#### TC-DASH-004 — `No module named 'quantumvault.web.dependencies'`
- Correct module is `quantumvault.web.routes.status`. Import `get_service` from there:
  ```python
  from quantumvault.web.routes.status import get_service
  ```

---

### Group I: PQC (TC-PQC-014)

#### TC-PQC-014 — grep hits tests_round2 file
- Fix: filter out matches from test files:
  ```python
  matches = [l for l in proc.stdout.strip().splitlines() if "tests_" not in l and "suspicious_patterns" not in l]
  passed = (len(matches) == 0)
  ```

---

### Group J: Submission (TC-SUB-003)

#### TC-SUB-003 — `"Self-Test PASSED"` not in stdout
- `setup.py` outputs: `"ALL ENVIRONMENT & POST-QUANTUM SELF-TESTS PASSED."`
- Fix: `passed = (proc.returncode == 0 and "self-test" in proc.stdout.lower() and "passed" in proc.stdout.lower())`

---

## HOW TO CONTINUE

### Step 1 — Fix all failing tests in `test_cases.py`

> **CRITICAL**: The file uses **CRLF line endings** (`\r\n`). Python `str.replace()` with `\n` patterns will NOT match.  
> Use `edit_file` tool with **exact matching strings** directly from `read_file` output, or write a Python script that reads/writes in binary or uses `content.replace(old, new)` matching the exact bytes in the file.

Recommended approach: Use `edit_file` with exact target strings as read from the file.

**Order of edits** (do them all in parallel where independent):
1. Fix TC-LOST-001 (`user['id']` → `user.get('actor_id')`)
2. Fix TC-LOST-004 (`owner_id=` → `asset_owner=`, `owner_access` → `owner_allowed`)
3. Fix TC-LOST-006 (replace MessagingSession call with proper handshake flow)
4. Fix TC-LOST-008 (`revoke_device` returns None, use `get_device()["status"]`)
5. Fix TC-LOST-010, 014 (`authenticate_device_response` → `is_device_active`)
6. Fix TC-LOST-015, 019 (`is_device_revoked` → `not is_device_active`)
7. Fix TC-LOST-016, 017, 021 (`get_device_status` → inline `is_device_active`)
8. Fix all TC-ROT-* (remove raw key bytes, `get_version` → `key_repo.get_version`, `state` → `status`)
9. Fix TC-TR-001, 003, 008 (`ApprovalRegistry.add(ApprovalChange(...))`)
10. Fix TC-TR-009 (`incident.title` → `incident.incident_type`)
11. Fix TC-AUD-002–011 (table `audit_log` → `audit_events`, `get_latest_hash` → `repo.get_last_entry()["entry_hash"]`, `"timestamp"` → `"event_time_utc"`)
12. Fix TC-AUTH-002 (`authenticate_device_response` → `is_device_active`)
13. Fix TC-AUTH-006 (`recovery_codes` → `recovery_credentials`)
14. Fix TC-MSG-001 to 011 (complete rewrite using correct API above)
15. Fix TC-RACE-003, 008
16. Fix TC-DASH-004 (`quantumvault.web.dependencies` → `quantumvault.web.routes.status`)
17. Fix TC-PQC-014 (filter out test-file matches from grep)
18. Fix TC-SUB-003 (case-insensitive PASSED check)

---

### Step 2 — Run tests and confirm ≥155/168 pass
```powershell
C:\Python313\python.exe -c "
from final_security_validation.test_cases import run_all_tests
res = run_all_tests()
failed = [r for r in res if not r.passed]
print(f'Total: {len(res)}, Passed: {len(res)-len(failed)}, Failed: {len(failed)}')
[print(f'{r.test_id} [{r.category}]: {r.actual[:80]}') for r in failed]
"
```

---

### Step 3 — Run the master runner to generate all 5 reports
```powershell
C:\Python313\python.exe final_security_validation\challenge-u-to-break.py
```
Expected output:
- `final_security_validation/reports/results.json`
- `final_security_validation/reports/vulnerabilities.json`
- `final_security_validation/reports/performance.json`
- `final_security_validation/reports/rubric_assessment.json`
- `final_security_validation/reports/FINAL_VALIDATION_REPORT.md`

---

### Step 4 — Git commit all `final_security_validation/` files
```powershell
git add final_security_validation/
git commit -m "feat(eval): complete extreme independent security validation suite (169 tests, 5 reports)"
git push origin feature/adversarial-eval
```

---

## KEY INTERFACE FACTS (Verified Against Actual Source)

| Component | Method / Attribute | Notes |
|-----------|-------------------|-------|
| `QuantumVaultService` | `.read(actor, asset, request_id)` | kwarg is `asset=`, NOT `asset_id=` |
| `QuantumVaultService` | `.revoke(actor: str)` | No `revoke_device` on service |
| `KeyRotationManager` | `.rotate_key(new_version_id, grace_seconds=30.0, rewrap_assets=True)` | No raw bytes 2nd arg |
| `KeyRotationManager` | `.key_repo.get_version(vid)` → dict with `status` field | NOT `mgr.get_version()`, NOT `state` |
| `KeyRotationManager` | `.key_repo.get_active_version()` | Returns dict with `version_id` |
| `KeyRotationManager` | `.expire_cutoff(version_id)` | Immediately retires a version |
| `KeyRotationManager` | `.get_key_for_version(vid)` | Raises `CryptoError` if retired/expired |
| `DeviceManager` | `.is_device_active(device_id)` | Returns `bool` |
| `DeviceManager` | `.get_device(device_id)` | Returns dict with `status` field |
| `DeviceManager` | `.revoke_device(device_id, reason)` | Returns `None` |
| `DeviceManager` | `.enroll_device(actor_id, device_id, public_key_b64)` | Returns dict with `status` |
| `PolicyEngine` | `.evaluate_access(actor, asset, asset_owner, is_disabled, role='viewer')` | kwarg `asset_owner`, rule is `"owner_allowed"` |
| `MLKEM768` | `.generate_keypair()` → `(ek, dk)` | ek=1184B, dk=2400B |
| `MLKEM768` | `.encapsulate(ek)` → `(ct, ss)` | |
| `MLKEM768` | `.decapsulate(secret_key_bytes, ciphertext_bytes)` | sk first, then ct |
| `MLDSA65` | `.generate_keypair()` → `(vk, sk)` | vk=1952B, sk=4032B |
| `MessagingHandshake` | Instance method: `hs = MessagingHandshake(); hs.generate_responder_offer(...)` | NOT classmethod |
| `MessagingSession` | `__init__(session_id, local_actor_id, local_device_id, remote_actor_id, remote_device_id, k_send, k_recv)` | 7 required args |
| `MessagingSession` | `.send_message(plaintext)` / `.receive_message(envelope)` | |
| `MessagingSession` | `.resume_session()` → raises `SecurityPolicyError` | |
| `ChunkedTransport` | `.segment_payload(message_id, payload_bytes)` → `list[dict]` | chunks are dicts |
| `ChunkedTransport` | `.reassemble(chunks)` → `(is_complete, payload_bytes, missing_indices)` | Returns tuple |
| `EncryptedOutbox` | `__init__(conn, local_storage_key=kek)` | kwarg `local_storage_key=` |
| `AuditLogger` | `.repo.get(request_id)` / `.repo.get_last_entry()` | No `.get_record()` or `.get_latest_hash()` |
| `AuditLogVerifier` | `.verify()` → `{"status", "total_records", "tampered", ...}` | |
| `ApprovalRegistry` | `.add(approval: ApprovalChange)` | Takes ONE dataclass arg |
| `ClassificationResult` | `.label` (NOT `.predicted_label`) | |
| `Incident` | `.incident_type` (NOT `.title`) | |
| DB Table | `audit_events` | NOT `audit_log` |
| DB Table | `recovery_credentials` | NOT `recovery_codes` |
| `revoke_device()` return | `None` | Does NOT return a dict |
| `IsolatedTestEnvironment` | `.initialize_vault()` → `QuantumVaultService` | Also sets `.service`, `.coordinator`, `.nodes` |
| `IsolatedTestEnvironment` | `.clean()` / `.close()` | Use `.close()` for full teardown |

---

## FILES STRUCTURE

```
final_security_validation/
├── README.md                          ✅ Done
├── mock_environment.py                ✅ Done
├── test_cases.py                      🔧 ~115/168 passing; needs interface fixes above
├── challenge-u-to-break.py            ✅ Done (wired correctly)
├── HANDOFF_NEXT_MODEL.md             ← This file
├── runtime/                           📂 Ephemeral test dirs created here
├── evidence/                          📂 Evidence text files
└── reports/                           📂 JSON + MD reports produced on run
```

---

## WHAT IS NOT DONE YET

1. ❌ All 168+ tests passing cleanly
2. ❌ Master runner completing end-to-end (blocked by test failures causing `run_benchmarks` crash)
3. ❌ All 5 JSON reports + FINAL_VALIDATION_REPORT.md generated
4. ❌ Git commit of `final_security_validation/`
5. ❌ Final terminal summary delivered to user

---

> **For the next model**: Start by applying the interface fixes from Group A–J above using `edit_file` with exact strings from the file. The file has CRLF endings, so use `read_file` first to confirm the exact text before each edit. After fixes, run the test suite, then the master runner.
