"""Encrypted offline outbox with post-reconnection authorization and revocation revalidation."""
import secrets
import sqlite3
from typing import Any, Callable

from quantumvault.core.errors import AuthorizationError, SecurityPolicyError
from quantumvault.crypto.encryption import AuthenticatedEncryption
from quantumvault.storage.db import transaction
from quantumvault.storage.repositories import (
    DeviceRepository,
    IdentityRepository,
    OfflineOutboxRepository,
    RevocationRepository,
)


class EncryptedOutbox:
    """Stores outgoing messages encrypted at rest when offline, and enforces
    strict fail-closed authorization checks upon network reconnection.
    """

    def __init__(self, conn: sqlite3.Connection, local_storage_key: bytes):
        self.conn = conn
        self.repo = OfflineOutboxRepository(conn)
        self.identities = IdentityRepository(conn)
        self.devices = DeviceRepository(conn)
        self.revocations = RevocationRepository(conn)
        self.cipher = AuthenticatedEncryption(local_storage_key)

    def enqueue(self, actor_id: str, device_id: str, recipient_id: str,
                raw_payload: str | bytes) -> str:
        """Encrypt payload at rest and enqueue in outbox table."""
        outbox_id = f"out-{secrets.token_hex(12)}"
        payload_bytes = raw_payload.encode("utf-8") if isinstance(raw_payload, str) else bytes(raw_payload)

        # Encrypt under local device storage key with actor-bound AAD
        aad = f"outbox:{outbox_id}:{actor_id}:{recipient_id}".encode("utf-8")
        ciphertext, nonce = self.cipher.encrypt(payload_bytes, associated_data=aad)

        self.repo.enqueue(
            outbox_id=outbox_id,
            actor_id=actor_id,
            device_id=device_id,
            recipient_id=recipient_id,
            payload_ciphertext=ciphertext,
            nonce=nonce
        )
        return outbox_id

    def flush(self, actor_id: str,
              dispatch_callback: Callable[[str, str, bytes], bool]) -> list[dict[str, Any]]:
        """Process pending outbox messages after reconnecting to network.
        
        Enforces FAIL-CLOSED authorization:
        1. Checks if sender actor has been revoked or disabled during offline period.
        2. Checks if recipient exists and is active.
        3. Decrypts locally stored payload and calls dispatch_callback.
        4. Updates status to 'delivered' or 'failed'.
        """
        pending = self.repo.list_pending(actor_id=actor_id)
        results: list[dict[str, Any]] = []

        # 1. Fail-closed check: verify sender actor has not been revoked or disabled
        if self.revocations.is_revoked(actor_id, entity_type="actor"):
            for item in pending:
                self.repo.increment_attempts(item["outbox_id"])
            raise AuthorizationError(f"Sender '{actor_id}' was revoked during offline period: outbox dispatch failed closed")

        ident = self.identities.get(actor_id)
        if not ident or ident["status"] != "active":
            for item in pending:
                self.repo.increment_attempts(item["outbox_id"])
            raise AuthorizationError(f"Sender '{actor_id}' is not active: outbox dispatch aborted")

        # 2. Claim and process each pending message atomically
        for item in pending:
            outbox_id = item["outbox_id"]
            device_id = item["device_id"]
            recipient_id = item["recipient_id"]

            if item.get("status") == "queued":
                with transaction(self.conn):
                    if not self.repo.claim_pending(outbox_id):
                        continue

            # Verify sending device was not individually revoked while offline
            if self.revocations.is_revoked(device_id, entity_type="device") or self.devices.is_revoked(device_id) and self.devices.get(device_id) is not None:
                with transaction(self.conn):
                    self.repo.increment_attempts(outbox_id)
                raise AuthorizationError(
                    f"Device '{device_id}' for '{actor_id}' was revoked during offline period: outbox dispatch failed closed"
                )

            # Verify recipient validity
            recip_ident = self.identities.get(recipient_id)
            if not recip_ident or recip_ident["status"] != "active" or self.revocations.is_revoked(recipient_id):
                with transaction(self.conn):
                    self.repo.increment_attempts(outbox_id)
                    self.repo.release_claim(outbox_id)
                results.append({"outbox_id": outbox_id, "status": "failed", "error": "recipient_inactive_or_revoked"})
                continue

            # Decrypt local payload
            aad = f"outbox:{outbox_id}:{actor_id}:{recipient_id}".encode("utf-8")
            try:
                plaintext_bytes = self.cipher.decrypt_bytes(
                    item["payload_ciphertext"],
                    item["nonce"],
                    associated_data=aad
                )
            except Exception as e:
                with transaction(self.conn):
                    self.repo.release_claim(outbox_id)
                results.append({"outbox_id": outbox_id, "status": "failed", "error": f"decryption_failed: {e}"})
                continue

            # Dispatch via callback
            success = dispatch_callback(actor_id, recipient_id, plaintext_bytes)
            if success:
                with transaction(self.conn):
                    self.repo.mark_delivered(outbox_id)
                results.append({"outbox_id": outbox_id, "status": "delivered"})
            else:
                with transaction(self.conn):
                    self.repo.increment_attempts(outbox_id)
                    self.repo.release_claim(outbox_id)
                results.append({"outbox_id": outbox_id, "status": "failed", "error": "dispatch_callback_failed"})

        return results
