"""Cryptographic key rotation, lifecycle state machine, and asset rewrapping."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import secrets
import sqlite3
import time
from typing import Any

from quantumvault.core.errors import CryptoError
from quantumvault.crypto.aad import (
    construct_key_version_aad,
    construct_legacy_key_version_aad,
    construct_legacy_resource_aad,
    construct_resource_aad,
)
from quantumvault.crypto.encryption import AuthenticatedEncryption
from quantumvault.storage.db import transaction
from quantumvault.storage.repositories import (
    AppStateRepository,
    AssetRepository,
    KeyVersionRepository,
)


class KeyRotationManager:
    """Manages multi-state key lifecycle (pre_active, active, grace_period, retired),
    grace periods, cutoff timestamps, and asset rewrapping."""

    def __init__(self, conn: sqlite3.Connection, kek: bytes):
        self.conn = conn
        self.kek = kek
        self.kek_cipher = AuthenticatedEncryption(kek)
        self.key_repo = KeyVersionRepository(conn)
        self.asset_repo = AssetRepository(conn)
        self.app_state = AppStateRepository(conn)

    def initialize_initial_version(self, version_id: str = "v1",
                                   initial_key_bytes: bytes | None = None) -> bytes:
        """Create or load the initial active master key version."""
        existing = self.key_repo.get_version(version_id)
        if existing:
            return self.get_key_for_version(version_id)

        raw_key = initial_key_bytes if initial_key_bytes else secrets.token_bytes(32)
        encrypted_bytes, nonce = self.kek_cipher.encrypt(
            raw_key.hex(),
            associated_data=construct_key_version_aad(version_id)
        )

        now_iso = datetime.now(timezone.utc).isoformat()
        with transaction(self.conn):
            self.key_repo.create_version(
                version_id=version_id,
                encrypted_key_bytes=encrypted_bytes,
                nonce=nonce,
                status="active",
                activated_at=now_iso
            )
            self.app_state.set("active_key_version", version_id)

        return raw_key

    def _decrypt_version_raw(self, record: dict[str, Any]) -> bytes:
        """Unwrap raw 256-bit key bytes from a key_versions row using the master KEK, supporting migration."""
        version_id = record["version_id"]
        # 1. Try canonical length-prefixed AAD
        try:
            key_hex = self.kek_cipher.decrypt(
                record["encrypted_key_bytes"],
                record["nonce"],
                associated_data=construct_key_version_aad(version_id)
            )
            return bytes.fromhex(key_hex)
        except Exception:
            pass

        # 2. Try legacy colon-separated AAD
        try:
            key_hex = self.kek_cipher.decrypt(
                record["encrypted_key_bytes"],
                record["nonce"],
                associated_data=construct_legacy_key_version_aad(version_id)
            )
            return bytes.fromhex(key_hex)
        except Exception as e:
            raise CryptoError(f"Failed to decrypt key version '{version_id}': {e}") from e

    def get_key_for_version(self, version_id: str) -> bytes:
        """Retrieve and decrypt the raw 256-bit key for a given version, enforcing lifecycle cutoffs."""
        record = self.key_repo.get_version(version_id)
        if not record:
            raise CryptoError(f"Key version '{version_id}' does not exist")

        status = record["status"]

        # 1. Check if explicitly retired
        if status == "retired":
            raise CryptoError(f"Key version '{version_id}' is permanently retired")

        # 2. Check if in grace period at or past cutoff timestamp
        now_dt = datetime.now(timezone.utc)
        if status == "grace_period" and record["cutoff_at"]:
            cutoff_dt = datetime.fromisoformat(record["cutoff_at"])
            if now_dt >= cutoff_dt:
                # Transition to retired
                with transaction(self.conn):
                    self.key_repo.update_status(version_id, status="retired")
                raise CryptoError(f"Key version '{version_id}' has expired past cutoff timestamp")

        return self._decrypt_version_raw(record)

    def get_cipher_for_version(self, version_id: str) -> AuthenticatedEncryption:
        """Instantiate an AuthenticatedEncryption cipher for the specified key version."""
        raw_key = self.get_key_for_version(version_id)
        return AuthenticatedEncryption(raw_key)

    def rotate_key(self, new_version_id: str, grace_seconds: float = 30.0,
                   rewrap_assets: bool = True) -> dict[str, Any]:
        """Perform atomic key rotation from current active key to new_version_id.
        
        1. Validate target version is unused (never reactivate retired versions).
        2. Create new key in 'pre_active'.
        3. Set previous key to 'grace_period' with cutoff timestamp.
        4. Promote new key to 'active'.
        5. Re-encrypt (rewrap) assets if requested.
        6. Record durable completion and duration in app_state.
        """
        t_start = time.perf_counter()
        active_rec = self.key_repo.get_active_version()
        old_version_id = active_rec["version_id"] if active_rec else "v1"

        if old_version_id == new_version_id:
            raise CryptoError(f"Cannot rotate to identical version '{new_version_id}'")

        existing_target = self.key_repo.get_version(new_version_id)
        if existing_target is not None:
            raise CryptoError(
                f"Cannot rotate to existing/retired key version '{new_version_id}' "
                f"(status: {existing_target['status']})"
            )

        now_dt = datetime.now(timezone.utc)
        cutoff_dt = now_dt + timedelta(seconds=grace_seconds)
        now_iso = now_dt.isoformat()
        cutoff_iso = cutoff_dt.isoformat()

        # Step A: Generate new raw key and encrypt under KEK in 'pre_active' state
        new_raw_key = secrets.token_bytes(32)
        aad = construct_key_version_aad(new_version_id)
        enc_bytes, nonce = self.kek_cipher.encrypt(new_raw_key.hex(), associated_data=aad)

        with transaction(self.conn):
            # Durable journal: mark rotation in progress
            self.app_state.set("key_rotation_status", f"in_progress:{old_version_id}->{new_version_id}")

            self.key_repo.create_version(
                version_id=new_version_id,
                encrypted_key_bytes=enc_bytes,
                nonce=nonce,
                status="pre_active"
            )

            # Step B: Transition old key to grace_period with cutoff
            if active_rec:
                self.key_repo.update_status(
                    old_version_id,
                    status="grace_period",
                    cutoff_at=cutoff_iso
                )

            # Step C: Promote new key to active
            self.key_repo.update_status(
                new_version_id,
                status="active",
                activated_at=now_iso
            )
            self.app_state.set("active_key_version", new_version_id)

        # Step D: Rewrap assets from old version to new version
        rewrapped_count = 0
        if rewrap_assets:
            new_cipher = AuthenticatedEncryption(new_raw_key)
            old_raw_key = self.get_key_for_version(old_version_id)
            old_cipher = AuthenticatedEncryption(old_raw_key)

            all_assets = self.asset_repo.list_all()
            with transaction(self.conn):
                for asset in all_assets:
                    if asset.get("key_version") != new_version_id:
                        asset_id = asset["asset_id"]
                        owner_id = asset["owner_actor_id"]
                        canonical_aad = construct_resource_aad(asset_id, owner_id)

                        # Decrypt under old cipher (supporting legacy AAD migration)
                        try:
                            body = old_cipher.decrypt(
                                asset["encrypted_body"],
                                asset["nonce"],
                                associated_data=canonical_aad
                            )
                        except Exception:
                            body = old_cipher.decrypt(
                                asset["encrypted_body"],
                                asset["nonce"],
                                associated_data=construct_legacy_resource_aad(asset_id, owner_id)
                            )

                        # Re-encrypt under new cipher with fresh nonce and canonical AAD
                        new_enc_body, new_nonce = new_cipher.encrypt(body, associated_data=canonical_aad)
                        self.asset_repo.update_encrypted_body(
                            asset_id=asset_id,
                            encrypted_body=new_enc_body,
                            nonce=new_nonce,
                            key_version=new_version_id
                        )
                        rewrapped_count += 1

        # Step E: Mark rotation completed durably
        with transaction(self.conn):
            self.app_state.set("key_rotation_status", f"completed:{new_version_id}")

        rotation_duration_ms = round((time.perf_counter() - t_start) * 1000.0, 4)
        return {
            "previous_version": old_version_id,
            "active_version": new_version_id,
            "rewrapped_count": rewrapped_count,
            "cutoff_at": cutoff_iso,
            "rotation_duration_ms": rotation_duration_ms,
            "status": "completed"
        }

    def expire_cutoff(self, version_id: str) -> None:
        """Immediately retire a version and set its cutoff to the past."""
        past_iso = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        with transaction(self.conn):
            self.key_repo.update_status(version_id, status="retired", cutoff_at=past_iso)

    def recover_interrupted_rotation(self) -> dict[str, Any] | None:
        """Recover from a crash or interruption during key rotation."""
        status = self.app_state.get("key_rotation_status")
        if not status or not status.startswith("in_progress:"):
            return None

        # Parse transition: "in_progress:v1->v2"
        transition = status.split(":", 1)[1]
        old_v, new_v = transition.split("->")

        new_rec = self.key_repo.get_version(new_v)
        old_rec = self.key_repo.get_version(old_v)
        if not new_rec or not old_rec:
            raise CryptoError(f"Cannot recover interrupted rotation '{transition}': missing key version record")

        # Unwrap keys directly via KEK so assets can finish migrating even if cutoff elapsed mid-crash
        new_cipher = AuthenticatedEncryption(self._decrypt_version_raw(new_rec))
        old_cipher = AuthenticatedEncryption(self._decrypt_version_raw(old_rec))

        all_assets = self.asset_repo.list_all()
        recovered_count = 0
        with transaction(self.conn):
            if new_rec["status"] == "pre_active":
                self.key_repo.update_status(new_v, status="active", activated_at=datetime.now(timezone.utc).isoformat())
            for asset in all_assets:
                if asset.get("key_version") != new_v:
                    asset_id = asset["asset_id"]
                    owner_id = asset["owner_actor_id"]
                    canonical_aad = construct_resource_aad(asset_id, owner_id)
                    try:
                        body = old_cipher.decrypt(
                            asset["encrypted_body"],
                            asset["nonce"],
                            associated_data=canonical_aad
                        )
                    except Exception:
                        body = old_cipher.decrypt(
                            asset["encrypted_body"],
                            asset["nonce"],
                            associated_data=construct_legacy_resource_aad(asset_id, owner_id)
                        )
                    new_enc, new_nonce = new_cipher.encrypt(body, associated_data=canonical_aad)
                    self.asset_repo.update_encrypted_body(
                        asset_id=asset_id,
                        encrypted_body=new_enc,
                        nonce=new_nonce,
                        key_version=new_v
                    )
                    recovered_count += 1

            self.app_state.set("active_key_version", new_v)
            self.app_state.set("key_rotation_status", f"completed:{new_v}")

        return {
            "recovered_transition": transition,
            "rewrapped_count": recovered_count,
            "status": "recovered"
        }
