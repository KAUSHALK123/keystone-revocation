QUANTUMVAULT — THREE LEVEL LOCAL CHALLENGE
=========================================
Keep all six Python files together. Extract the folder outside your repo.
Use only your own trusted QuantumVault implementation and assigned sandbox.
The challenge copies selected source into temporary directories and creates
synthetic state. This is not an OS-level isolation sandbox; do not run
untrusted code. No intentional external network traffic or shared-service load.

Windows PowerShell (adjust the paths):
  cd "D:\Downloads\QuantumVault-3-Level-Challenge"
  python --version
  python test-easy.py --self-test
  python test-easy.py --repo "E:\ps4-oncemore"
  python test-normal.py --repo "E:\ps4-oncemore"
  python test-extreme.py --repo "E:\ps4-oncemore" --rounds 8 --seed 987654321

Use the same Python interpreter/environment as your project, including pqcrypto
and web dependencies. No dependency installation is attempted. Do not start the
website; the adaptive web probes use local ASGI calls when available.

Profiles are separate, not cumulative:
  Easy: 5 groups — basic access, revocation, reset, PQC and opaque identifiers.
  Normal: 10 groups — multi-asset owners, isolation, cryptographic generation
  changes, malformed input, storage, audit, detection and web origin checks.
  Extreme: 16 groups — mixed concurrent read/audit/KEM/revoke model checking,
  competing setup, two commit boundaries, rollback isolation, ciphertext
  substitution, noncanonical KEM key, revocation races, replay oracle,
  multiprocess recovery, backup authentication, audit deletion, detector
  mutations and web session lifecycle.
The package reuses selected V5/V6 helpers and adds new combined tests.

Default JSON reports: easy-results.json, normal-results.json, extreme-results.json.
Existing reports are never overwritten. Choose another filename for a rerun:
  python test-extreme.py --repo "E:\ps4-oncemore" --rounds 8 --seed 789 --report extreme-run2.json
List or select tests:
  python test-extreme.py --list
  python test-extreme.py --repo "E:\ps4-oncemore" --only recovery --report recovery.json

Exit codes: 0 = every selected group passed; 1 = failure/error; 2 = skip(s)
with no failure/error. SKIP is not PASS. Adaptive internal probes require
recognizable interfaces and positive controls. A missing dependency or missing
fixture may skip. Some hardening and direct-storage tests exceed the public
adapter contract; interpret them against the threat model, not as automatic
organizer disqualification. --rounds controls bounded history repetitions;
random secrets and actual process scheduling vary even with the same seed.

Verification of this package: Python syntax, profile registries and inherited
history oracle self-tests checked; Easy non-PQC groups and Normal multi-asset
check smoke-tested on an independent mock adapter. The target project source
and pqcrypto were not available here, so full execution against QuantumVault
and the new extreme combined probes have not been verified. This is not an
official hidden test suite, complete security audit or proof of security.
