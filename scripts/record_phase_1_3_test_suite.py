"""Runs the complete QuantumVault Phase 1.3 test suite and writes evidence."""
from datetime import datetime, timezone
from pathlib import Path
import sys
import time
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))


def main():
    suite = unittest.defaultTestLoader.discover(str(ROOT_DIR / "tests"), top_level_dir=str(ROOT_DIR))
    evidence_path = ROOT_DIR / "evidence" / "phase-1.3" / "test_suite_results.txt"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    t0 = time.perf_counter()
    with open(evidence_path, "w", encoding="utf-8") as f:
        f.write("QUANTUMVAULT PHASE 1.3 AUTOMATED TEST SUITE EXECUTION RESULTS\n")
        f.write("=" * 70 + "\n")
        f.write(f"Timestamp: {datetime.now(timezone.utc).isoformat()}\n")
        f.write("Test Modules: Unit Tests, Telemetry, Detection, Messaging, PQC, Lab, Combined\n\n")

        runner = unittest.TextTestRunner(stream=f, verbosity=2)
        result = runner.run(suite)

    elapsed = time.perf_counter() - t0
    print(f"Ran {result.testsRun} tests in {elapsed:.2f}s. Failures: {len(result.failures)}, Errors: {len(result.errors)}")
    if not result.wasSuccessful():
        sys.exit(1)


if __name__ == "__main__":
    main()
