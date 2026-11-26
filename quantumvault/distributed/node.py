"""Mock service node implementing local PEP caching, heartbeats, and fail-closed isolation."""
from __future__ import annotations
from pathlib import Path
import sqlite3
import time
from typing import Any

from quantumvault.config import get_db_path, get_state_dir
from quantumvault.core.service import QuantumVaultService
from quantumvault.storage.db import get_connection


class ServiceNode:
    """Independent service node instance with local PEP cache and health monitoring."""

    def __init__(self, node_id: str, address: str | None = None,
                 state_dir: Path | None = None, db_path: Path | None = None,
                 heartbeat_threshold_seconds: float = 5.0):
        self.node_id = node_id
        self.address = address or f"cluster://{node_id}"
        self.state_dir = state_dir or get_state_dir()
        self.db_path = db_path or get_db_path(self.state_dir)
        self.heartbeat_threshold_seconds = heartbeat_threshold_seconds

        self.status = "online"
        self.authority_connected = True
        self.last_heartbeat = time.time()
        self.current_epoch = 1
        self.active_key_version = "v1"

        # Local Policy Enforcement Point (PEP) in-memory cache
        self.cached_revocations: set[tuple[str, str]] = set()  # (entity_id, entity_type)

        # Underlying persistent service
        self.service = QuantumVaultService(db_path=self.db_path, state_dir=self.state_dir)

    def is_healthy(self) -> bool:
        """Check if node is online, authority is reachable, and heartbeat is fresh (fail-closed policy)."""
        if not self.authority_connected:
            return False
        if self.status != "online":
            return False
        elapsed = time.time() - self.last_heartbeat
        if elapsed > self.heartbeat_threshold_seconds:
            return False
        return True

    def set_authority_unreachable(self) -> None:
        """Simulate communication failure to the Security Authority."""
        self.authority_connected = False

    def set_authority_reachable(self) -> None:
        """Restore communication to the Security Authority."""
        self.authority_connected = True
        self.send_heartbeat()

    def send_heartbeat(self) -> None:
        """Refresh node heartbeat timestamp."""
        self.last_heartbeat = time.time()
        if self.status == "offline":
            self.status = "online"

    def set_offline(self) -> None:
        """Simulate network partition or node failure."""
        self.status = "offline"

    def set_online(self) -> None:
        """Recover node from offline state."""
        self.status = "online"
        self.last_heartbeat = time.time()

    def simulate_heartbeat_timeout(self, seconds_ago: float = 10.0) -> None:
        """Artificially age the heartbeat to test partition threshold."""
        self.last_heartbeat = time.time() - seconds_ago

    def apply_revocation(self, entity_id: str, entity_type: str = "actor") -> None:
        """Instantaneously update local PEP cache upon receiving broadcast."""
        self.cached_revocations.add((entity_id, entity_type))

    def sync(self, epoch: int, active_key_version: str, revocations: set[tuple[str, str]]) -> None:
        """Synchronize node state with authority."""
        self.current_epoch = epoch
        self.active_key_version = active_key_version
        self.cached_revocations = set(revocations)
        self.send_heartbeat()

    def read(self, actor: str, asset: str, request_id: str, device_id: str | None = None) -> dict[str, Any]:
        """Process read request with local PEP caching and fail-closed enforcement."""
        # 1. Fail-closed partition policy: If disconnected or partition drift > threshold
        if not self.is_healthy():
            try:
                self.service.audit_logger.log_decision(
                    request_id=request_id,
                    actor_id=actor,
                    op="read",
                    asset_id=asset,
                    decision="deny",
                    rule="node_offline_fail_closed"
                )
            except Exception:
                pass
            return {
                "decision": "deny",
                "rule": "node_offline_fail_closed"
            }

        # 2. Check local PEP cache before storage query
        if (actor, "actor") in self.cached_revocations or (device_id and (device_id, "device") in self.cached_revocations):
            try:
                self.service.audit_logger.log_decision(
                    request_id=request_id,
                    actor_id=actor,
                    op="read",
                    asset_id=asset,
                    decision="deny",
                    rule="revoked_cached"
                )
            except Exception:
                pass
            return {"decision": "deny"}

        # 3. Delegate to underlying engine
        return self.service.read(actor=actor, asset=asset, request_id=request_id)

    def protected_read(self, actor: str, asset: str, challenge: str, public_key: str,
                       device_id: str | None = None) -> dict[str, Any]:
        """Process protected read with fail-closed check."""
        if not self.is_healthy():
            return {"decision": "deny"}

        if (actor, "actor") in self.cached_revocations:
            return {"decision": "deny"}

        if device_id and (device_id, "device") in self.cached_revocations:
            return {"decision": "deny"}

        return self.service.protected_read(
            actor=actor,
            asset=asset,
            challenge=challenge,
            public_key=public_key
        )

    def close(self) -> None:
        """Clean up underlying service connection."""
        self.service.close()
