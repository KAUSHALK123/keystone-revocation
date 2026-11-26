"""Runs the complete test suite and writes clean formatted evidence."""
from pathlib import Path
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

def main():
    suite = unittest.defaultTestLoader.discover(str(ROOT_DIR / "tests"), top_level_dir=str(ROOT_DIR))
    evidence_path = ROOT_DIR / "evidence" / "phase-1.2" / "test_suite_results.txt"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(evidence_path, "w", encoding="utf-8") as f:
        f.write("QUANTUMVAULT PHASE 1.2 AUTOMATED TEST SUITE EXECUTION RESULTS\n")
        f.write("=" * 70 + "\n\n")
        runner = unittest.TextTestRunner(stream=f, verbosity=2)
        result = runner.run(suite)
        
    print(f"Ran {result.testsRun} tests. Failures: {len(result.failures)}, Errors: {len(result.errors)}")
    if not result.wasSuccessful():
        sys.exit(1)

if __name__ == "__main__":
    main()
