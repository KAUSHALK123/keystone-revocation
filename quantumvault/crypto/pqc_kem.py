"""NIST ML-KEM-768 post-quantum cryptographic key encapsulation mechanism."""
import base64
import logging
from typing import Tuple

from quantumvault.core.errors import CryptoError

logger = logging.getLogger(__name__)

# Constants according to NIST FIPS 203 / pqcrypto 0.4.0
PUBLIC_KEY_SIZE = 1184
CIPHERTEXT_SIZE = 1088
SHARED_SECRET_SIZE = 32
SECRET_KEY_SIZE = 2400


class MLKEM768:
    """Wrapper around pqcrypto.kem.ml_kem_768 providing standardized KEM operations."""

    def __init__(self):
        try:
            import pqcrypto.kem.ml_kem_768 as kem
            self._kem = kem
            self.algorithm = "ML-KEM-768"
        except ImportError as e:
            raise CryptoError(f"Post-quantum library pqcrypto.kem.ml_kem_768 is required: {e}") from e

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a fresh (public_key, secret_key) pair."""
        try:
            pk, sk = self._kem.generate_keypair()
            if len(pk) != PUBLIC_KEY_SIZE or len(sk) != SECRET_KEY_SIZE:
                raise CryptoError("Generated keypair has invalid byte length")
            return pk, sk
        except Exception as e:
            raise CryptoError(f"Key generation failed: {e}") from e

    def encapsulate(self, public_key_bytes: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate against a raw ML-KEM-768 public key to produce (ciphertext, shared_secret)."""
        if not isinstance(public_key_bytes, (bytes, bytearray)):
            raise CryptoError("Public key must be bytes")
        if len(public_key_bytes) != PUBLIC_KEY_SIZE:
            raise CryptoError(
                f"Invalid ML-KEM-768 public key length: expected {PUBLIC_KEY_SIZE}, got {len(public_key_bytes)}"
            )
        self.validate_public_key_canonicality(bytes(public_key_bytes))
        try:
            # pqcrypto.kem.ml_kem_768 uses encrypt() for encapsulation
            ciphertext, shared_secret = self._kem.encrypt(bytes(public_key_bytes))
            if len(ciphertext) != CIPHERTEXT_SIZE or len(shared_secret) != SHARED_SECRET_SIZE:
                raise CryptoError("Encapsulation returned unexpected component sizes")
            return ciphertext, shared_secret
        except Exception as e:
            raise CryptoError(f"Encapsulation failed: {e}") from e

    def decapsulate(self, secret_key_bytes: bytes, ciphertext_bytes: bytes) -> bytes:
        """Decapsulate ciphertext using secret key to recover the 32-byte shared secret."""
        if len(secret_key_bytes) != SECRET_KEY_SIZE:
            raise CryptoError(f"Invalid secret key length: expected {SECRET_KEY_SIZE}, got {len(secret_key_bytes)}")
        if len(ciphertext_bytes) != CIPHERTEXT_SIZE:
            raise CryptoError(f"Invalid ciphertext length: expected {CIPHERTEXT_SIZE}, got {len(ciphertext_bytes)}")
        try:
            # pqcrypto.kem.ml_kem_768 uses decrypt() for decapsulation
            shared_secret = self._kem.decrypt(bytes(secret_key_bytes), bytes(ciphertext_bytes))
            if len(shared_secret) != SHARED_SECRET_SIZE:
                raise CryptoError("Decapsulation returned unexpected secret size")
            return shared_secret
        except Exception as e:
            raise CryptoError(f"Decapsulation failed: {e}") from e

    @staticmethod
    def encode_public_key(public_key_bytes: bytes) -> str:
        """Encode raw public key to standard Base64 ASCII string."""
        return base64.b64encode(public_key_bytes).decode("ascii")

    @staticmethod
    def validate_public_key_canonicality(public_key_bytes: bytes) -> None:
        """Validate FIPS 203 canonical encoding: all 768 coefficients must be < q=3329."""
        if len(public_key_bytes) != PUBLIC_KEY_SIZE:
            raise CryptoError(f"Invalid ML-KEM-768 public key length: {len(public_key_bytes)}")
        # 1152 bytes encode 768 coefficients as 384 3-byte pairs
        for j in range(384):
            off = j * 3
            b0 = public_key_bytes[off]
            b1 = public_key_bytes[off + 1]
            b2 = public_key_bytes[off + 2]
            c0 = b0 | ((b1 & 0x0F) << 8)
            c1 = (b1 >> 4) | (b2 << 4)
            if c0 >= 3329 or c1 >= 3329:
                raise CryptoError(
                    f"Non-canonical ML-KEM-768 public key: coefficient exceeds modulus q=3329 at pair {j}"
                )

    @staticmethod
    def decode_public_key(b64_key: str) -> bytes:
        """Strictly decode standard Base64 public key string to raw bytes and enforce canonical coefficients."""
        if not isinstance(b64_key, str) or not b64_key.strip():
            raise CryptoError("Public key must be a non-empty Base64 string")
        try:
            raw = base64.b64decode(b64_key.strip(), validate=True)
            if len(raw) != PUBLIC_KEY_SIZE:
                raise CryptoError(f"Decoded public key length is {len(raw)}, expected {PUBLIC_KEY_SIZE}")
            MLKEM768.validate_public_key_canonicality(raw)
            return raw
        except (ValueError, TypeError) as e:
            raise CryptoError(f"Malformed Base64 public key: {e}") from e

    @staticmethod
    def encode_ciphertext(ciphertext_bytes: bytes) -> str:
        """Encode raw KEM ciphertext to standard Base64 ASCII string."""
        return base64.b64encode(ciphertext_bytes).decode("ascii")
