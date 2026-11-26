"""Protected resource vault with authenticated encryption at rest and key rotation support."""
import sqlite3
from typing import Any, Tuple

from quantumvault.core.errors import CryptoError
from quantumvault.crypto.encryption import AuthenticatedEncryption
from quantumvault.storage.repositories import AssetRepository


class ResourceVault:
    """Manages encrypted storage and retrieval of protected resources."""

    def __init__(self, conn: sqlite3.Connection,
                 cipher: AuthenticatedEncryption | None = None,
                 key_resolver: Any = None):
        self.repo = AssetRepository(conn)
        self.cipher = cipher
        self.key_resolver = key_resolver

    def _get_cipher(self, key_version: str = "v1") -> AuthenticatedEncryption:
        """Resolve the appropriate cipher for the requested key version."""
        if self.key_resolver is not None:
            return self.key_resolver.get_cipher_for_version(key_version)
        if self.cipher is not None:
            return self.cipher
        raise CryptoError("No cipher or key resolver available in ResourceVault")

    def store_resource(self, asset_id: str, owner_id: str, plaintext_body: str,
                       key_version: str = "v1") -> None:
        """Encrypt and persist a resource under AES-256-GCM."""
        aad = f"{asset_id}:{owner_id}".encode("utf-8")
        cipher = self._get_cipher(key_version)
        ciphertext, nonce = cipher.encrypt(plaintext_body, associated_data=aad)
        self.repo.store(asset_id, owner_id, ciphertext, nonce, key_version=key_version)

    def retrieve_resource(self, asset_id: str) -> Tuple[str, str] | None:
        """Retrieve and decrypt an authorized resource.
        
        Returns:
            (owner_id, plaintext_body) or None if not found
        """
        record = self.repo.get(asset_id)
        if not record:
            return None
        
        owner_id = record["owner_actor_id"]
        ciphertext = record["encrypted_body"]
        nonce = record["nonce"]
        key_ver = record.get("key_version") or "v1"
        
        aad = f"{asset_id}:{owner_id}".encode("utf-8")
        cipher = self._get_cipher(key_ver)
        plaintext_body = cipher.decrypt(ciphertext, nonce, associated_data=aad)
        return owner_id, plaintext_body

    def get_owner(self, asset_id: str) -> str | None:
        """Lookup owner without decrypting ciphertext body."""
        return self.repo.get_owner(asset_id)
