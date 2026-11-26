#!/usr/bin/env python3
"""QuantumVault Setup & Post-Quantum Cryptographic Self-Test.

Verifies Python version (>=3.11) and performs self-tests for NIST FIPS 203 (ML-KEM-768)
and NIST FIPS 204 (ML-DSA-65) post-quantum primitives.
Exits 0 on success, 1 on failure.
"""
from __future__ import annotations

from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

MIN_PYTHON = (3, 11)
if sys.version_info < MIN_PYTHON:
    sys.exit(
        f"ERROR: QuantumVault requires Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer. "
        f"Detected Python {sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]}."
    )


def run_kem_self_test() -> None:
    """Validate ML-KEM-768 key encapsulation and decapsulation."""
    try:
        from quantumvault.crypto.pqc_kem import MLKEM768
    except ImportError as e:
        sys.exit(f"ERROR: Failed to import post-quantum KEM module: {e}")

    kem = MLKEM768()
    pk, sk = kem.generate_keypair()
    if not pk or not sk:
        sys.exit("ERROR: ML-KEM-768 keypair generation returned empty keys.")

    ciphertext, shared_secret_sender = kem.encapsulate(pk)
    shared_secret_receiver = kem.decapsulate(sk, ciphertext)

    if shared_secret_sender != shared_secret_receiver:
        sys.exit("ERROR: ML-KEM-768 self-test failed: decapsulated secret does not match sender secret.")

    print("  [PASS] NIST FIPS 203 ML-KEM-768 (Kyber768) encapsulation/decapsulation verified.")


def run_dsa_self_test() -> None:
    """Validate ML-DSA-65 signature generation and verification."""
    try:
        from quantumvault.crypto.pqc_dsa import MLDSA65
    except ImportError as e:
        sys.exit(f"ERROR: Failed to import post-quantum DSA module: {e}")

    dsa = MLDSA65()
    pk, sk = dsa.generate_keypair()
    if not pk or not sk:
        sys.exit("ERROR: ML-DSA-65 keypair generation returned empty keys.")

    message = b"QuantumVault Zero-Trust Identity Guard Self-Test Payload"
    sig = dsa.sign(sk, message)

    if not dsa.verify(pk, message, sig):
        sys.exit("ERROR: ML-DSA-65 valid signature verification failed.")

    tampered = message + b"_tampered"
    if dsa.verify(pk, tampered, sig):
        sys.exit("ERROR: ML-DSA-65 failed closed check: tampered signature accepted as valid.")

    print("  [PASS] NIST FIPS 204 ML-DSA-65 (Dilithium3) sign/verify & tamper-rejection verified.")


def main() -> int:
    print("==================================================")
    print("QuantumVault Clean-Machine Environment Verification")
    print(f"Python: {sys.version.split()[0]} ({sys.platform})")
    print("==================================================")

    try:
        import pqcrypto
        print(f"  [PASS] Native PQC library loaded: pqcrypto (location: {pqcrypto.__file__})")
    except ImportError as e:
        sys.exit(
            f"ERROR: Failed to import 'pqcrypto': {e}\n"
            "Please ensure you installed dependencies with:\n"
            "  pip install -r requirements-core.txt\n"
            "Prebuilt wheels are available for Windows (x86_64), Linux (manylinux), and macOS."
        )

    run_kem_self_test()
    run_dsa_self_test()

    print("==================================================")
    print("ALL ENVIRONMENT & POST-QUANTUM SELF-TESTS PASSED.")
    print("==================================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
