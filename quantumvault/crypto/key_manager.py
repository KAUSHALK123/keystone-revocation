"""Key management and derivation for QuantumVault internal storage keys."""
from __future__ import annotations
from pathlib import Path
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from quantumvault.config import get_vault_key_path
from quantumvault.core.errors import CryptoError


def derive_vault_key(key_material: str) -> bytes:
    """Derive a 256-bit AES storage key from input key material via HKDF-SHA-256."""
    if not key_material:
        raise CryptoError("Key material cannot be empty")
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"quantumvault-salt-v1",
        info=b"quantumvault-storage-key-v1"
    )
    return hkdf.derive(key_material.encode("utf-8"))


def initialize_vault_key(key_material: str | None = None, key_path: Path | None = None) -> bytes:
    """Initialize and persist the master vault encryption key in the state directory."""
    target_path = key_path or get_vault_key_path()
    
    if key_material:
        key = derive_vault_key(key_material)
    else:
        key = secrets.token_bytes(32)
        
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_bytes(key)
    return key


def load_vault_key(key_path: Path | None = None) -> bytes:
    """Load the master vault encryption key from the designated state directory."""
    target_path = key_path or get_vault_key_path()
    if not target_path.exists():
        # Fall back to initializing a default random key if not yet set
        return initialize_vault_key(key_path=target_path)
    
    key = target_path.read_bytes()
    if len(key) != 32:
        raise CryptoError(f"Vault key file has invalid length: expected 32, got {len(key)}")
    return key
