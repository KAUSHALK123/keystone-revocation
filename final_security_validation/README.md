# QuantumVault Extreme Independent Security Validation

This directory contains the independent, adversarial security validation suite and automated judge simulation for **QuantumVault (Yugaantar DevForge Track 4: Key Identity Guard)**.

## Architecture

- `challenge-u-to-break.py`: Master test orchestrator executing baseline verification, synthetic environment initialization, 150+ adversarial test cases, benchmarks, and report generation.
- `mock_environment.py`: Synthetic enterprise environment supporting 6 users, 12 devices, 100+ assets, 5 services, and isolated local SQLite runtime states.
- `test_cases.py`: Over 150 independent test cases covering all 14 evaluation categories.
- `runtime/`: Disposable isolated databases, keys, and sockets.
- `evidence/`: Artifacts, traces, and verification outputs.
- `reports/`:
  - `FINAL_VALIDATION_REPORT.md`: Comprehensive 20-section audit report.
  - `results.json`: Granular test execution results.
  - `vulnerabilities.json`: Confirmed security findings and severity ratings.
  - `rubric_assessment.json`: 100-point hackathon scoring simulation.
  - `performance.json`: Monotonic benchmark statistics.

## Usage

```bash
# Run complete test suite (default)
python final_security_validation/challenge-u-to-break.py

# Run quick verification
python final_security_validation/challenge-u-to-break.py --quick

# Run specific category
python final_security_validation/challenge-u-to-break.py --category revocation
python final_security_validation/challenge-u-to-break.py --category distributed
python final_security_validation/challenge-u-to-break.py --category crypto
```
