"""Cryptographic primitives: ML-KEM-768, HMAC-SHA-256 proofs, and AES-256-GCM."""
from quantumvault.crypto.encryption import AuthenticatedEncryption
from quantumvault.crypto.hmac_proof import generate_proof, verify_proof
from quantumvault.crypto.pqc_kem import MLKEM768

__all__ = ["MLKEM768", "generate_proof", "verify_proof", "AuthenticatedEncryption"]
