"""Core application service coordinating IAM, storage, cryptography, and auditing."""
from pathlib import Path
import secrets
import sqlite3
from typing import Any

from quantumvault.audit.logger import AuditLogger
from quantumvault.config import (
    get_db_path,
    get_epoch_anchor_path,
    get_state_dir,
    get_vault_key_path,
)
from quantumvault.core.errors import AuthorizationError, CryptoError, QuantumVaultError
from quantumvault.crypto.encryption import AuthenticatedEncryption
from quantumvault.crypto.hmac_proof import generate_proof, zeroize
from quantumvault.crypto.key_manager import initialize_vault_key, load_vault_key
from quantumvault.crypto.pqc_kem import MLKEM768
from quantumvault.crypto.rotation import KeyRotationManager
from quantumvault.iam.policy import PolicyEngine
from quantumvault.storage.db import get_connection, init_db, reset_state, transaction
from quantumvault.storage.repositories import (
    AppStateRepository,
    AssetRepository,
    IdentityRepository,
    RevocationRepository,
)
from quantumvault.vault.resources import ResourceVault


class QuantumVaultService:
    """High-assurance service implementing the complete Adapter Contract v1 operations."""

    def __init__(self, db_path: Path | None = None, state_dir: Path | None = None):
        self.state_dir = state_dir or get_state_dir()
        self.db_path = db_path or get_db_path(self.state_dir)
        self.conn = get_connection(self.db_path)
        try:
            init_db(self.conn)
            self.app_state = AppStateRepository(self.conn)
            self.identities = IdentityRepository(self.conn)
            self.revocations = RevocationRepository(self.conn)
            self.audit_logger = AuditLogger(self.conn)
            self.pqc = MLKEM768()
        except Exception:
            self.close()
            raise

    def _get_vault(self) -> ResourceVault | None:
        """Instantiate the resource vault if setup has been completed and key exists."""
        key_path = get_vault_key_path(self.state_dir)
        if not key_path.exists() and self.app_state.get("ready") != "true":
            return None
        key = load_vault_key(key_path)
        rotation_mgr = KeyRotationManager(self.conn, key)
        cipher = AuthenticatedEncryption(key)
        return ResourceVault(self.conn, cipher=cipher, key_resolver=rotation_mgr)

    def setup(self, owners: dict[str, str], contents: dict[str, str],
              disabled: list[str], key_material: str) -> dict[str, Any]:
        """Operation 'setup': initialize clean isolated state."""
        with transaction(self.conn):
            reset_state(self.conn)

            # Reset external epoch anchor scoped to this state_dir on clean setup
            anchor_path = get_epoch_anchor_path(self.state_dir)
            if anchor_path.exists():
                try:
                    anchor_path.unlink()
                except OSError:
                    pass

            # 1. Initialize master vault encryption key and initial key version v1
            vault_key = initialize_vault_key(key_material, get_vault_key_path(self.state_dir))
            rotation_mgr = KeyRotationManager(self.conn, vault_key)
            rotation_mgr.initialize_initial_version("v1", vault_key)
            cipher = AuthenticatedEncryption(vault_key)
            vault = ResourceVault(self.conn, cipher=cipher, key_resolver=rotation_mgr)

            # 2. Persist disabled identities
            disabled_set = set(disabled or [])
            for actor in disabled_set:
                self.identities.upsert(actor, status="disabled", role="viewer")
                self.revocations.revoke(actor, entity_type="actor", reason="initial_disabled_list")

            # 3. Persist asset owners and identities
            for asset_id, owner_id in (owners or {}).items():
                if owner_id not in disabled_set:
                    self.identities.upsert(owner_id, status="active", role="viewer")

                body = (contents or {}).get(asset_id, "")
                vault.store_resource(asset_id, owner_id, body)

            # 4. Record application ready status
            self.app_state.set("ready", "true")

        return {"ready": True}

    def read(self, actor: str, asset: str, request_id: str) -> dict[str, Any]:
        """Operation 'read': authorize and retrieve stored plaintext body."""
        # Reject conflicting request ID reuse to prevent audit desynchronization
        if self.audit_logger.get_record(request_id) is not None:
            return {"decision": "deny"}

        vault = self._get_vault()
        owner_id = vault.get_owner(asset) if vault else None
        is_disabled = self.identities.is_disabled(actor) or self.revocations.is_revoked(actor)

        decision, rule = PolicyEngine.evaluate_access(actor, asset, owner_id, is_disabled)

        # Commit audit decision immutably
        with transaction(self.conn):
            self.audit_logger.log_decision(
                request_id=request_id,
                actor_id=actor,
                op="read",
                asset_id=asset,
                decision=decision,
                rule=rule
            )

        if decision == "allow" and vault is not None:
            res = vault.retrieve_resource(asset)
            if not res:
                return {"decision": "deny"}
            _, body = res
            return {"decision": "allow", "body": body}

        # Zero-Knowledge Denial: disclose no body, keys, or internal data
        return {"decision": "deny"}

    def revoke(self, actor: str) -> dict[str, Any]:
        """Operation 'revoke': permanently revoke actor access credentials."""
        with transaction(self.conn):
            self.identities.disable(actor)
            self.revocations.revoke(actor, entity_type="actor", reason="contract_v1_revocation")
        return {}

    def audit(self, request_id: str) -> dict[str, Any]:
        """Operation 'audit': retrieve historical decision for request ID."""
        record = self.audit_logger.get_record(request_id)
        if record:
            return {
                "request_id": record["request_id"],
                "decision": record["decision"]
            }
        return {"error": "unknown_request"}

    def protected_read(self, actor: str, asset: str, challenge: str, public_key: str) -> dict[str, Any]:
        """Operation 'protected_read': post-quantum KEM encapsulation and proof exchange."""
        vault = self._get_vault()
        owner_id = vault.get_owner(asset) if vault else None
        is_disabled = self.identities.is_disabled(actor) or self.revocations.is_revoked(actor)

        # 1. Authorization strictly before any cryptographic operations
        decision, rule = PolicyEngine.evaluate_access(actor, asset, owner_id, is_disabled)
        if decision != "allow" or vault is None:
            with transaction(self.conn):
                self.audit_logger.log_decision(
                    request_id=f"pread-{secrets.token_hex(12)}",
                    actor_id=actor,
                    op="protected_read",
                    asset_id=asset,
                    decision="deny",
                    rule=rule,
                )
            return {"decision": "deny"}

        res = vault.retrieve_resource(asset)
        if not res:
            return {"decision": "deny"}
        _, body = res

        # 2. Strict public key decoding and post-quantum encapsulation
        try:
            pk_bytes = self.pqc.decode_public_key(public_key)
            ciphertext, shared_secret = self.pqc.encapsulate(pk_bytes)
        except CryptoError:
            with transaction(self.conn):
                self.audit_logger.log_decision(
                    request_id=f"pread-{secrets.token_hex(12)}",
                    actor_id=actor,
                    op="protected_read",
                    asset_id=asset,
                    decision="deny",
                    rule="invalid_public_key",
                )
            return {"decision": "deny"}

        # 3. Compute lowercase hexadecimal HMAC-SHA-256 proof over (challenge + body)
        secret_buf = bytearray(shared_secret)
        try:
            proof = generate_proof(secret_buf, challenge, body)
            b64_ciphertext = self.pqc.encode_ciphertext(ciphertext)
            with transaction(self.conn):
                self.audit_logger.log_decision(
                    request_id=f"pread-{secrets.token_hex(12)}",
                    actor_id=actor,
                    op="protected_read",
                    asset_id=asset,
                    decision="allow",
                    rule=rule,
                )
            return {
                "ciphertext": b64_ciphertext,
                "proof": proof
            }
        finally:
            # Best-effort zeroization of mutable buffer (CPython bytes cannot be zeroed in-place)
            zeroize(secret_buf)

    def close(self) -> None:
        """Close database connection cleanly."""
        try:
            self.conn.close()
        except Exception:
            pass
