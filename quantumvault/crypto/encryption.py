"""Authenticated symmetric encryption (AES-256-GCM) for protected resource bodies."""
import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from quantumvault.core.errors import CryptoError

NONCE_SIZE = 12  # 96-bit standard GCM nonce
KEY_SIZE = 32    # 256-bit AES key


class AuthenticatedEncryption:
    """AES-256-GCM authenticated cipher with fresh random nonces per encryption."""

    def __init__(self, key: bytes):
        if len(key) != KEY_SIZE:
            raise CryptoError(f"AES-256-GCM requires a 32-byte key, got {len(key)}")
        self._key = key
        self._cipher = AESGCM(key)

    def encrypt_bytes(self, data: bytes, associated_data: bytes | None = None) -> tuple[bytes, bytes]:
        """Encrypt raw bytes with a fresh CSPRNG nonce.
        
        Returns:
            (ciphertext_with_tag, nonce)
        """
        if not isinstance(data, (bytes, bytearray)):
            raise CryptoError("Data must be bytes or bytearray")
        
        nonce = secrets.token_bytes(NONCE_SIZE)
        try:
            ciphertext = self._cipher.encrypt(nonce, bytes(data), associated_data)
            return ciphertext, nonce
        except Exception as e:
            raise CryptoError(f"Encryption failed: {e}") from e

    def decrypt_bytes(self, ciphertext: bytes, nonce: bytes, associated_data: bytes | None = None) -> bytes:
        """Authenticate and decrypt ciphertext, returning raw bytes."""
        if len(nonce) != NONCE_SIZE:
            raise CryptoError(f"Invalid nonce length: expected {NONCE_SIZE}, got {len(nonce)}")
        
        try:
            return self._cipher.decrypt(nonce, ciphertext, associated_data)
        except InvalidTag as e:
            raise CryptoError("Ciphertext integrity verification failed (invalid authentication tag)") from e
        except Exception as e:
            raise CryptoError(f"Decryption failed: {e}") from e

    def encrypt(self, plaintext: str | bytes, associated_data: bytes | None = None) -> tuple[bytes, bytes]:
        """Encrypt UTF-8 plaintext (or raw bytes) with a fresh CSPRNG nonce.
        
        Returns:
            (ciphertext_with_tag, nonce)
        """
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode("utf-8")
        elif isinstance(plaintext, (bytes, bytearray)):
            plaintext_bytes = bytes(plaintext)
        else:
            raise CryptoError("Plaintext must be a string or bytes")
        
        nonce = secrets.token_bytes(NONCE_SIZE)
        try:
            ciphertext = self._cipher.encrypt(nonce, plaintext_bytes, associated_data)
            return ciphertext, nonce
        except Exception as e:
            raise CryptoError(f"Encryption failed: {e}") from e

    def decrypt(self, ciphertext: bytes, nonce: bytes, associated_data: bytes | None = None) -> str:
        """Authenticate and decrypt ciphertext using the provided nonce.
        
        Raises CryptoError if ciphertext has been modified or tag fails verification.
        """
        raw_bytes = self.decrypt_bytes(ciphertext, nonce, associated_data)
        try:
            return raw_bytes.decode("utf-8")
        except UnicodeDecodeError as e:
            raise CryptoError("Decrypted data is not valid UTF-8 string") from e
