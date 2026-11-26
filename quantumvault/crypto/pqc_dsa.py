"""NIST ML-DSA-65 post-quantum digital signature mechanism (FIPS 204)."""
from __future__ import annotations
import base64
import logging
from typing import Tuple

from quantumvault.core.errors import CryptoError

logger = logging.getLogger(__name__)

# Constants according to NIST FIPS 204 / pqcrypto 0.4.0
PUBLIC_KEY_SIZE = 1952
SECRET_KEY_SIZE = 4032
SIGNATURE_SIZE = 3309


class MLDSA65:
    """Wrapper around pqcrypto.sign.ml_dsa_65 providing post-quantum digital signatures."""

    def __init__(self):
        try:
            import pqcrypto.sign.ml_dsa_65 as dsa
            self._dsa = dsa
            self.algorithm = "ML-DSA-65"
        except ImportError as e:
            raise CryptoError(f"Post-quantum library pqcrypto.sign.ml_dsa_65 is required: {e}") from e

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a fresh (public_key, secret_key) pair.
        
        Returns:
            (public_key: 1952 bytes, secret_key: 4032 bytes)
        """
        try:
            pk, sk = self._dsa.generate_keypair()
            if len(pk) != PUBLIC_KEY_SIZE or len(sk) != SECRET_KEY_SIZE:
                raise CryptoError("Generated ML-DSA keypair has invalid byte length")
            return pk, sk
        except Exception as e:
            raise CryptoError(f"ML-DSA keypair generation failed: {e}") from e

    def sign(self, secret_key_bytes: bytes, message: bytes | str) -> bytes:
        """Sign a message using the ML-DSA-65 secret key.
        
        Returns:
            Raw signature bytes (3309 bytes)
        """
        if len(secret_key_bytes) != SECRET_KEY_SIZE:
            raise CryptoError(f"Invalid ML-DSA secret key length: expected {SECRET_KEY_SIZE}, got {len(secret_key_bytes)}")
        
        msg_bytes = message.encode("utf-8") if isinstance(message, str) else bytes(message)
        try:
            sig = self._dsa.sign(secret_key_bytes, msg_bytes)
            if len(sig) != SIGNATURE_SIZE:
                raise CryptoError(f"ML-DSA signature returned unexpected size: {len(sig)}")
            return sig
        except Exception as e:
            raise CryptoError(f"ML-DSA signing failed: {e}") from e

    def verify(self, public_key_bytes: bytes, message: bytes | str, signature_bytes: bytes) -> bool:
        """Verify an ML-DSA-65 digital signature against a message.
        
        Returns:
            True if signature is valid, False otherwise.
        """
        if len(public_key_bytes) != PUBLIC_KEY_SIZE:
            return False
        if len(signature_bytes) != SIGNATURE_SIZE:
            return False
        
        msg_bytes = message.encode("utf-8") if isinstance(message, str) else bytes(message)
        try:
            return bool(self._dsa.verify(public_key_bytes, msg_bytes, signature_bytes))
        except Exception:
            return False

    @staticmethod
    def encode_public_key(public_key_bytes: bytes) -> str:
        """Encode raw public key to standard Base64 string."""
        return base64.b64encode(public_key_bytes).decode("ascii")

    @staticmethod
    def decode_public_key(b64_key: str) -> bytes:
        """Decode Base64 string to raw public key bytes."""
        try:
            raw = base64.b64decode(b64_key.strip(), validate=True)
            if len(raw) != PUBLIC_KEY_SIZE:
                raise CryptoError(f"Invalid ML-DSA public key length: expected {PUBLIC_KEY_SIZE}, got {len(raw)}")
            return raw
        except Exception as e:
            raise CryptoError(f"Malformed Base64 ML-DSA public key: {e}") from e

    @staticmethod
    def encode_signature(signature_bytes: bytes) -> str:
        """Encode raw signature to standard Base64 string."""
        return base64.b64encode(signature_bytes).decode("ascii")

    @staticmethod
    def decode_signature(b64_sig: str) -> bytes:
        """Decode Base64 string to raw signature bytes."""
        try:
            raw = base64.b64decode(b64_sig.strip(), validate=True)
            if len(raw) != SIGNATURE_SIZE:
                raise CryptoError(f"Invalid ML-DSA signature length: expected {SIGNATURE_SIZE}, got {len(raw)}")
            return raw
        except Exception as e:
            raise CryptoError(f"Malformed Base64 ML-DSA signature: {e}") from e
