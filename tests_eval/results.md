## SUMMARY
Passed 26 / 28. Estimated deductions: 0 Critical (0 pts), 0 High (0 pts), 2 Medium (-6 pts), 0 Low (0 pts). Simulated Score: 94 / 100.

## FAILURES
### T26: Bandit Static Code Analysis (CWE-89 SQL Injection Risk)
- **ID and name**: T26 - Bandit Static Code Analysis
- **Severity**: Medium (Dynamic string formatting used in SQL statements rather than parameterized identifiers)
- **Exact steps/command to reproduce**:
  `bandit -q -r quantumvault track4_service.py -f json`
- **Expected vs actual**:
  - Expected: 0 medium or high severity findings from static security analysis.
  - Actual: 2 medium-severity CWE-89 warnings flagged in `quantumvault/storage/repositories.py` (lines 241 and 447).
- **Evidence**:
  ```python
  # Line 241:
  self.conn.execute(f"UPDATE key_versions SET {', '.join(fields)} WHERE version_id = ?;", params)
  # Line 447:
  cursor = self.conn.execute(f"SELECT * FROM telemetry_events {order};")
  ```
- **Suspected root cause**: `quantumvault/storage/repositories.py:241` and `quantumvault/storage/repositories.py:447` construct query clauses via f-string interpolation instead of whitelisted/parameterized mappings.

### T28: Threat-Model Claims vs Reality (Omitted Test Telemetry & Hidden C-Dependencies)
- **ID and name**: T28 - Threat Model Claims Verification
- **Severity**: Medium (Claims of clean offline test pass and zero dependencies contradicted by omitted dataset and C-library requirements)
- **Exact steps/command to reproduce**:
  `python -m unittest discover tests -v` on fresh clone without running external `git clone` commands.
- **Expected vs actual**:
  - Expected: All claimed 171 tests pass self-contained from repo root with zero external network cloning.
  - Actual: Practice telemetry dataset `references/track4-toolkit/practice/events.csv` is absent from repository; `track4_service.py` requires compiled C-extension `pqcrypto==0.4.0` (liboqs) and Python 3.11+, failing on stock Python 3.9.
- **Evidence**:
  ```
  FileNotFoundError: Telemetry file not found: references/track4-toolkit/practice/events.csv
  CryptoError: Post-quantum library pqcrypto.kem.ml_kem_768 is required: No module named 'pqcrypto'
  ```
- **Suspected root cause**: `README.md:14`, `README.md:22`, `README.md:144` claim 100% test pass on practice events, but `references/track4-toolkit` was added to `.gitignore` / unbundled.

## WARNINGS (not failing, but risky)
1. **Windows SQLite File Handle Locks during Tempdir Cleanup**:
   In test suites and CLI runs on Windows, unclosed SQLite database connections cause `[WinError 32] The process cannot access the file because it is being used by another process` during directory cleanup. Connections must be explicitly closed before temporary folder disposal.
2. **PowerShell UTF-8 BOM Injection into STDIN**:
   Piping JSON via PowerShell (`echo '...' | python track4_service.py`) prepends a UTF-8 Byte Order Mark (`\ufeff`), which causes Python's standard `json.loads()` to reject the payload unless `.strip('\ufeff')` is implemented.
3. **Assert Statements Used in Production Test Runners**:
   Bandit flagged 149 B101 warnings for `assert` statements inside `quantumvault/testing/`. When Python is run with optimizations (`-O`), these assertions are stripped out.

## UNTESTABLE (and why)
1. **Official Toolkit Practice Events (`references/track4-toolkit/practice/events.csv`)**:
   Cannot run official 22 practice event end-to-end telemetry playback tests (`test_practice_dataset_full_classification`) offline because the practice dataset CSV was not committed into the repository and requires external git clone from ScalerOpenSourceLabs.
2. **Online Dependency Audit (`pip-audit`)**:
   Cannot complete live PyPI vulnerability database lookup in an air-gapped/offline sandbox without network access.

## CLEAN-MACHINE SETUP ISSUES
1. **Windows System32 Python Stub Hang**:
   On Windows systems with a 0-byte `C:\Windows\System32\python` file in system PATH, running `python` hangs indefinitely or fails. Runtimes must explicitly invoke `python.exe` or `py.exe`.
2. **Python 3.9 Incompatibility**:
   The repository uses PEP 604 type unions (`Path | None`, `str | None`) across `quantumvault/config.py`, `quantumvault/storage/db.py`, and `quantumvault/core/service.py` without `from __future__ import annotations`. When executed under Python 3.9, the entire test suite fails at load time with `TypeError: unsupported operand type(s) for |: 'type' and 'NoneType'`. Requires Python 3.11+ as specified in documentation.
3. **Native C Extension Build Requirement (`pqcrypto==0.4.0`)**:
   `pqcrypto` requires pre-built binary wheels or MSVC C compiler tools. Under environments where binary wheels are unavailable, build from source fails without C build tools.
4. **Missing Practice Data Directory**:
   `references/track4-toolkit` is an empty folder on clean clone, causing `python references/track4-toolkit/validate.py` to fail immediately.

## THREAT-MODEL CLAIMS NOT BACKED BY TESTS
1. **"Zero External Dependencies Judging Backend"**:
   `README.md` claims `track4_service.py` has zero external dependencies. In reality, `QuantumVaultService.__init__` unconditionally instantiates `MLKEM768()`, requiring the `pqcrypto` native C module even for basic classical read operations.
2. **"171/171 Automated Tests Passed (100% PASS)"**:
   `README.md` Section 5.1 claims 171/171 passed. Out of the box on a clean checkout, running `python -m unittest discover tests` yields `FAILED (failures=4, errors=113)` due to missing `events.csv` and unclosed database file locks on Windows.
3. **"Accessible Five-Minute Fallback Video Link"**:
   `templates/two-page-brief.md` line 33 contains placeholder text `[PENDING USER UPLOAD]` rather than a verified accessible URL.

## PERFORMANCE TABLE
| Operation | p50 Latency | p95 Latency | Benchmark Threshold (< 2000 ms) | Peak Memory | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Normal Read Flow (Setup + Authorized Read)** | **3.018 ms** | **5.274 ms** | `< 2000 ms` | **0.03 MB** | **PASS** |
| **Revoke Flow (Revoke + Denied Read)** | **5.322 ms** | **10.421 ms** | `< 2000 ms` | **0.03 MB** | **PASS** |
| **Cryptographic Replay Detection** | **0.003 ms** | **0.008 ms** | `< 2000 ms` | **< 0.01 MB** | **PASS** |
| **Independent Hash Chain Block Verification** | **0.007 ms** | **0.015 ms** | `< 2000 ms` | **< 0.01 MB** | **PASS** |
