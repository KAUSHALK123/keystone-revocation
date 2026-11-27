"""Protected resource vault with authenticated encryption at rest and key rotation support."""
from __future__ import annotations
import sqlite3
from typing import Any, Tuple

from quantumvault.core.errors import CryptoError
from quantumvault.crypto.aad import construct_legacy_resource_aad, construct_resource_aad
from quantumvault.crypto.encryption import AuthenticatedEncryption
from quantumvault.storage.repositories import AssetRepository


class ResourceVault:
    """Manages encrypted storage and retrieval of protected resources."""

    def __init__(self, conn: sqlite3.Connection,
                 cipher: AuthenticatedEncryption | None = None,
                 key_resolver: Any = None):
        self.conn = conn
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
        """Encrypt and persist a resource under AES-256-GCM with canonical unambiguous AAD."""
        aad = construct_resource_aad(asset_id, owner_id)
        cipher = self._get_cipher(key_version)
        ciphertext, nonce = cipher.encrypt(plaintext_body, associated_data=aad)
        self.repo.store(asset_id, owner_id, ciphertext, nonce, key_version=key_version)

    def retrieve_resource(self, asset_id: str) -> Tuple[str, str] | None:
        """Retrieve and decrypt an authorized resource, supporting transparent migration.
        
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
        cipher = self._get_cipher(key_ver)

        # 1. Primary path: decrypt with canonical unambiguous AAD
        canonical_aad = construct_resource_aad(asset_id, owner_id)
        try:
            plaintext_body = cipher.decrypt(ciphertext, nonce, associated_data=canonical_aad)
            return owner_id, plaintext_body
        except CryptoError:
            pass

        # 2. Legacy fallback and migration: try legacy colon-separated AAD
        legacy_aad = construct_legacy_resource_aad(asset_id, owner_id)
        try:
            plaintext_body = cipher.decrypt(ciphertext, nonce, associated_data=legacy_aad)
            # Seamless migration: re-encrypt under canonical AAD with fresh nonce
            new_ct, new_nonce = cipher.encrypt(plaintext_body, associated_data=canonical_aad)
            self.repo.update_encrypted_body(
                asset_id=asset_id,
                encrypted_body=new_ct,
                nonce=new_nonce,
                key_version=key_ver
            )
            return owner_id, plaintext_body
        except Exception as e:
            raise CryptoError(f"Authenticated decryption failed for asset '{asset_id}': {e}") from e

    def get_owner(self, asset_id: str) -> str | None:
        """Lookup owner without decrypting ciphertext body."""
        return self.repo.get_owner(asset_id)
