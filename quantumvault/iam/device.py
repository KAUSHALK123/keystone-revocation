"""Device enrollment, lifecycle management, and proof-of-possession registry."""
import base64
import sqlite3
from typing import Any

from quantumvault.core.errors import AuthorizationError, IdentityError
from quantumvault.storage.repositories import DeviceRepository, IdentityRepository, RevocationRepository


class DeviceManager:
    """Manages actor-device bindings, individual device revocations, and status queries."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.device_repo = DeviceRepository(conn)
        self.identity_repo = IdentityRepository(conn)
        self.revocation_repo = RevocationRepository(conn)

    def enroll_device(self, actor_id: str, device_id: str, public_key_b64: str) -> dict[str, Any]:
        """Enroll a new device bound to an existing, active actor identity."""
        if not actor_id or not device_id or not public_key_b64:
            raise IdentityError("actor_id, device_id, and public_key_b64 are required")

        # Validate that actor exists and is active
        identity = self.identity_repo.get(actor_id)
        if not identity:
            raise AuthorizationError(f"Cannot enroll device for non-existent actor '{actor_id}'")

        if self.identity_repo.is_disabled(actor_id) or self.revocation_repo.is_revoked(actor_id, "actor"):
            raise AuthorizationError(f"Cannot enroll device for disabled/revoked actor '{actor_id}'")

        # Ensure base64 public key is syntactically valid (Ed25519: 32 bytes, ML-DSA-65: 1952 bytes)
        try:
            raw_key = base64.b64decode(public_key_b64, validate=True)
            if len(raw_key) not in (32, 1952):
                raise IdentityError(f"Expected 32-byte Ed25519 or 1952-byte ML-DSA-65 public key, got {len(raw_key)} bytes")
        except Exception as e:
            raise IdentityError(f"Invalid Base64 public key: {e}") from e

        self.device_repo.enroll(
            device_id=device_id,
            actor_id=actor_id,
            public_key_b64=public_key_b64,
            status="active"
        )
        return {
            "device_id": device_id,
            "actor_id": actor_id,
            "status": "active"
        }

    def revoke_device(self, device_id: str, reason: str = "lost_or_stolen") -> None:
        """Permanently revoke a specific device without affecting other actor devices."""
        dev = self.device_repo.get(device_id)
        if not dev:
            # Idempotently record revocation even if unknown
            self.revocation_repo.revoke(device_id, entity_type="device", reason=reason)
            return

        self.device_repo.revoke(device_id)
        self.revocation_repo.revoke(device_id, entity_type="device", reason=reason)

    def is_device_active(self, device_id: str) -> bool:
        """Check if device is active and bound actor is also active."""
        dev = self.device_repo.get(device_id)
        if not dev:
            return False
        if dev["status"] != "active":
            return False
        if self.revocation_repo.is_revoked(device_id, entity_type="device"):
            return False

        # If parent actor identity is disabled or revoked, the device cannot be active
        actor_id = dev["actor_id"]
        if self.identity_repo.is_disabled(actor_id) or self.revocation_repo.is_revoked(actor_id, "actor"):
            return False

        return True

    def get_device(self, device_id: str) -> dict[str, Any] | None:
        """Lookup device details by ID."""
        return self.device_repo.get(device_id)

    def list_actor_devices(self, actor_id: str) -> list[dict[str, Any]]:
        """List all devices registered to an actor."""
        return self.device_repo.list_for_actor(actor_id)
