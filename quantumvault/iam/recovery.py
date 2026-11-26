"""Emergency account recovery and device re-enrollment protocols."""
import hashlib
import re
import secrets
import sqlite3
from typing import Any

from quantumvault.core.errors import AuthenticationError, IdentityError
from quantumvault.iam.device import DeviceManager
from quantumvault.storage.db import transaction
from quantumvault.storage.repositories import IdentityRepository, RecoveryRepository, RevocationRepository


def _normalize_code(code: str) -> str:
    """Strip hyphens, spaces, and normalize to uppercase."""
    return re.sub(r"[^A-Za-z0-9]", "", code).upper()


def _hash_code(code: str, salt: str) -> str:
    """Compute salted SHA-256 verifier."""
    norm = _normalize_code(code)
    data = (salt + norm).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class RecoveryManager:
    """Manages high-entropy single-use recovery codes and lost device recovery flows."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.repo = RecoveryRepository(conn)
        self.identity_repo = IdentityRepository(conn)
        self.device_mgr = DeviceManager(conn)
        self.revocation_repo = RevocationRepository(conn)

    def generate_recovery_codes(self, actor_id: str, count: int = 5) -> list[str]:
        """Generate high-entropy recovery codes for an actor and store their salted hashes."""
        if not self.identity_repo.get(actor_id):
            raise IdentityError(f"Actor '{actor_id}' does not exist")
        if self.identity_repo.is_disabled(actor_id):
            raise IdentityError(f"Cannot generate recovery codes for disabled actor '{actor_id}'")

        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # Unambiguous characters
        plaintext_codes: list[str] = []

        with transaction(self.conn):
            for _ in range(count):
                parts = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(4)]
                code = "-".join(parts)
                salt = secrets.token_hex(16)
                code_hash = _hash_code(code, salt)

                self.repo.store_code(actor_id=actor_id, code_hash=code_hash, salt=salt)
                plaintext_codes.append(code)

        return plaintext_codes

    def verify_and_consume(self, actor_id: str, code: str) -> bool:
        """Atomically verify and consume a single-use recovery code.
        
        Returns True if code was valid and consumed, False otherwise.
        """
        if not code or not actor_id:
            return False

        with transaction(self.conn):
            if self.identity_repo.is_disabled(actor_id) or self.revocation_repo.is_revoked(actor_id, "actor"):
                return False

            cursor = self.conn.execute(
                "SELECT id, code_hash, salt FROM recovery_credentials WHERE actor_id = ? AND used_at IS NULL;",
                (actor_id,)
            )
            candidates = cursor.fetchall()

            matched_hash = None
            for candidate in candidates:
                expected_hash = candidate["code_hash"]
                salt = candidate["salt"]
                calculated_hash = _hash_code(code, salt)
                if secrets.compare_digest(calculated_hash, expected_hash):
                    matched_hash = expected_hash
                    break

            if not matched_hash:
                return False

            return self.repo.consume_code(actor_id, matched_hash)

    def recover_and_replace_device(self, actor_id: str, recovery_code: str,
                                   new_device_id: str, new_public_key_b64: str,
                                   revoke_existing_devices: bool = True) -> dict[str, Any]:
        """Verify recovery code and enroll a replacement device, revoking compromised ones."""
        with transaction(self.conn):
            consumed = self.verify_and_consume(actor_id, recovery_code)
            if not consumed:
                raise AuthenticationError("Invalid or previously used recovery code")

            if revoke_existing_devices:
                existing_devices = self.device_mgr.list_actor_devices(actor_id)
                for dev in existing_devices:
                    if dev["device_id"] != new_device_id and dev["status"] == "active":
                        self.device_mgr.revoke_device(dev["device_id"], reason="recovery_replacement")

            # Enroll replacement device
            res = self.device_mgr.enroll_device(
                actor_id=actor_id,
                device_id=new_device_id,
                public_key_b64=new_public_key_b64
            )
            return {
                "status": "recovered",
                "actor_id": actor_id,
                "new_device_id": new_device_id,
                "replacement_confirmed": True
            }
