"""HMAC-SHA-256 proof generation and constant-time verification for Adapter Contract v1."""
import hashlib
import hmac
from typing import Union

from quantumvault.core.errors import CryptoError


def generate_proof(shared_secret: bytes, challenge: str, stored_body: str) -> str:
    """Generate exact lowercase hexadecimal HMAC-SHA-256 proof.
    
    Contract Rule:
    HMAC-SHA-256 keyed by the shared secret over UTF-8 bytes of:
    `challenge + stored_body`, in that order, without a separator.
    """
    if not isinstance(shared_secret, (bytes, bytearray)):
        raise CryptoError("Shared secret must be bytes")
    if len(shared_secret) != 32:
        raise CryptoError(f"Shared secret must be exactly 32 bytes, got {len(shared_secret)}")
    if not isinstance(challenge, str):
        raise CryptoError("Challenge must be a string")
    if not isinstance(stored_body, str):
        raise CryptoError("Stored body must be a string")
    
    payload = (challenge + stored_body).encode("utf-8")
    digest = hmac.new(bytes(shared_secret), payload, hashlib.sha256).hexdigest()
    return digest.lower()


def verify_proof(proof: str, shared_secret: bytes, challenge: str, stored_body: str) -> bool:
    """Verify an HMAC proof using constant-time string comparison."""
    if not isinstance(proof, str):
        return False
    expected = generate_proof(shared_secret, challenge, stored_body)
    return hmac.compare_digest(proof.lower().strip(), expected)


def zeroize(buf: Union[bytearray, None]) -> None:
    """Best-effort in-place zeroization of mutable byte buffers."""
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0
