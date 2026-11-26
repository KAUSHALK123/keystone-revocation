"""Data access repositories for QuantumVault entities."""
from datetime import datetime, timezone
import sqlite3
from typing import Any


class AppStateRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def set(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO app_state (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP;",
            (key, value)
        )

    def get(self, key: str) -> str | None:
        cursor = self.conn.execute("SELECT value FROM app_state WHERE key = ?;", (key,))
        row = cursor.fetchone()
        return row["value"] if row else None


class IdentityRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def upsert(self, actor_id: str, status: str = "active", role: str = "viewer") -> None:
        self.conn.execute(
            "INSERT INTO identities (actor_id, status, role) VALUES (?, ?, ?) "
            "ON CONFLICT(actor_id) DO UPDATE SET status = excluded.status, role = excluded.role, updated_at = CURRENT_TIMESTAMP;",
            (actor_id, status, role)
        )

    def get(self, actor_id: str) -> dict[str, Any] | None:
        cursor = self.conn.execute("SELECT * FROM identities WHERE actor_id = ?;", (actor_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def list_all(self) -> list[dict[str, Any]]:
        cursor = self.conn.execute("SELECT * FROM identities ORDER BY actor_id ASC;")
        return [dict(row) for row in cursor.fetchall()]

    def is_disabled(self, actor_id: str) -> bool:
        cursor = self.conn.execute(
            "SELECT status FROM identities WHERE actor_id = ?;", (actor_id,)
        )
        row = cursor.fetchone()
        if not row:
            cursor_rev = self.conn.execute(
                "SELECT 1 FROM revocations WHERE actor_id = ?;", (actor_id,)
            )
            return cursor_rev.fetchone() is not None
        return row["status"] == "disabled"

    def disable(self, actor_id: str) -> None:
        self.conn.execute(
            "INSERT INTO identities (actor_id, status, role) VALUES (?, 'disabled', 'viewer') "
            "ON CONFLICT(actor_id) DO UPDATE SET status = 'disabled', updated_at = CURRENT_TIMESTAMP;",
            (actor_id,)
        )


class DeviceRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def enroll(self, device_id: str, actor_id: str, public_key_b64: str, status: str = "active") -> None:
        self.conn.execute(
            "INSERT INTO devices (device_id, actor_id, public_key_b64, status, enrolled_at) "
            "VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP) "
            "ON CONFLICT(device_id) DO UPDATE SET public_key_b64 = excluded.public_key_b64, "
            "status = excluded.status, revoked_at = NULL;",
            (device_id, actor_id, public_key_b64, status)
        )

    def get(self, device_id: str) -> dict[str, Any] | None:
        cursor = self.conn.execute("SELECT * FROM devices WHERE device_id = ?;", (device_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def list_for_actor(self, actor_id: str) -> list[dict[str, Any]]:
        cursor = self.conn.execute(
            "SELECT * FROM devices WHERE actor_id = ? ORDER BY enrolled_at ASC;", (actor_id,)
        )
        return [dict(row) for row in cursor.fetchall()]

    def list_all(self) -> list[dict[str, Any]]:
        cursor = self.conn.execute("SELECT * FROM devices ORDER BY device_id ASC;")
        return [dict(row) for row in cursor.fetchall()]

    def revoke(self, device_id: str) -> None:
        self.conn.execute(
            "UPDATE devices SET status = 'revoked', revoked_at = CURRENT_TIMESTAMP WHERE device_id = ?;",
            (device_id,)
        )

    def is_revoked(self, device_id: str) -> bool:
        cursor = self.conn.execute("SELECT status FROM devices WHERE device_id = ?;", (device_id,))
        row = cursor.fetchone()
        if not row:
            return True
        return row["status"] == "revoked"

    def is_active(self, device_id: str) -> bool:
        cursor = self.conn.execute("SELECT status FROM devices WHERE device_id = ?;", (device_id,))
        row = cursor.fetchone()
        if not row:
            return False
        return row["status"] == "active"


class RecoveryRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def store_code(self, actor_id: str, code_hash: str, salt: str) -> None:
        self.conn.execute(
            "INSERT INTO recovery_credentials (actor_id, code_hash, salt, created_at) "
            "VALUES (?, ?, ?, CURRENT_TIMESTAMP);",
            (actor_id, code_hash, salt)
        )

    def get_valid_code(self, actor_id: str, code_hash: str) -> dict[str, Any] | None:
        cursor = self.conn.execute(
            "SELECT * FROM recovery_credentials WHERE actor_id = ? AND code_hash = ? AND used_at IS NULL;",
            (actor_id, code_hash)
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def consume_code(self, actor_id: str, code_hash: str) -> bool:
        cursor = self.conn.execute(
            "UPDATE recovery_credentials SET used_at = CURRENT_TIMESTAMP "
            "WHERE actor_id = ? AND code_hash = ? AND used_at IS NULL;",
            (actor_id, code_hash)
        )
        return cursor.rowcount > 0


class AssetRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def store(self, asset_id: str, owner_actor_id: str, encrypted_body: bytes, nonce: bytes,
              key_version: str = "v1") -> None:
        self.conn.execute(
            "INSERT INTO assets (asset_id, owner_actor_id, encrypted_body, nonce, key_version) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(asset_id) DO UPDATE SET owner_actor_id = excluded.owner_actor_id, "
            "encrypted_body = excluded.encrypted_body, nonce = excluded.nonce, "
            "key_version = excluded.key_version, updated_at = CURRENT_TIMESTAMP;",
            (asset_id, owner_actor_id, encrypted_body, nonce, key_version)
        )

    def update_encrypted_body(self, asset_id: str, encrypted_body: bytes, nonce: bytes,
                              key_version: str) -> None:
        self.conn.execute(
            "UPDATE assets SET encrypted_body = ?, nonce = ?, key_version = ?, "
            "updated_at = CURRENT_TIMESTAMP WHERE asset_id = ?;",
            (encrypted_body, nonce, key_version, asset_id)
        )

    def get(self, asset_id: str) -> dict[str, Any] | None:
        cursor = self.conn.execute("SELECT * FROM assets WHERE asset_id = ?;", (asset_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_owner(self, asset_id: str) -> str | None:
        cursor = self.conn.execute("SELECT owner_actor_id FROM assets WHERE asset_id = ?;", (asset_id,))
        row = cursor.fetchone()
        return row["owner_actor_id"] if row else None

    def list_all(self) -> list[dict[str, Any]]:
        cursor = self.conn.execute("SELECT * FROM assets ORDER BY asset_id ASC;")
        return [dict(row) for row in cursor.fetchall()]


class RevocationRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def revoke(self, actor_id: str, entity_type: str = "actor", reason: str = "administrative_revocation") -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO revocations (actor_id, entity_type, reason) VALUES (?, ?, ?);",
            (actor_id, entity_type, reason)
        )

    def is_revoked(self, actor_id: str, entity_type: str = "actor") -> bool:
        cursor = self.conn.execute(
            "SELECT 1 FROM revocations WHERE actor_id = ? AND entity_type = ?;",
            (actor_id, entity_type)
        )
        return cursor.fetchone() is not None

    def list_all(self) -> list[dict[str, Any]]:
        cursor = self.conn.execute("SELECT * FROM revocations ORDER BY id ASC;")
        return [dict(row) for row in cursor.fetchall()]


class KeyVersionRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def create_version(self, version_id: str, encrypted_key_bytes: bytes, nonce: bytes,
                       status: str = "pre_active", algorithm: str = "AES-256-GCM",
                       activated_at: str | None = None, cutoff_at: str | None = None) -> None:
        self.conn.execute(
            "INSERT INTO key_versions (version_id, algorithm, encrypted_key_bytes, nonce, status, activated_at, cutoff_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(version_id) DO UPDATE SET encrypted_key_bytes = excluded.encrypted_key_bytes, "
            "nonce = excluded.nonce, status = excluded.status, activated_at = excluded.activated_at, "
            "cutoff_at = excluded.cutoff_at;",
            (version_id, algorithm, encrypted_key_bytes, nonce, status, activated_at, cutoff_at)
        )

    def get_version(self, version_id: str) -> dict[str, Any] | None:
        cursor = self.conn.execute("SELECT * FROM key_versions WHERE version_id = ?;", (version_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_active_version(self) -> dict[str, Any] | None:
        cursor = self.conn.execute(
            "SELECT * FROM key_versions WHERE status = 'active' ORDER BY version_id DESC LIMIT 1;"
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def update_status(self, version_id: str, status: str,
                      activated_at: str | None = None, cutoff_at: str | None = None) -> None:
        fields = ["status = ?"]
        params: list[Any] = [status]
        if activated_at is not None:
            fields.append("activated_at = ?")
            params.append(activated_at)
        if cutoff_at is not None:
            fields.append("cutoff_at = ?")
            params.append(cutoff_at)
        params.append(version_id)
        self.conn.execute(
            f"UPDATE key_versions SET {', '.join(fields)} WHERE version_id = ?;",
            params
        )

    def list_all(self) -> list[dict[str, Any]]:
        cursor = self.conn.execute("SELECT * FROM key_versions ORDER BY version_id ASC;")
        return [dict(row) for row in cursor.fetchall()]


class ServiceNodeRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def register_node(self, node_id: str, address: str, status: str = "online",
                      epoch: int = 1, active_key: str = "v1") -> None:
        self.conn.execute(
            "INSERT INTO service_nodes (node_id, address, status, last_heartbeat, current_epoch, active_key_version) "
            "VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?, ?) "
            "ON CONFLICT(node_id) DO UPDATE SET address = excluded.address, status = excluded.status, "
            "last_heartbeat = CURRENT_TIMESTAMP, current_epoch = excluded.current_epoch, "
            "active_key_version = excluded.active_key_version;",
            (node_id, address, status, epoch, active_key)
        )

    def update_heartbeat(self, node_id: str, status: str = "online") -> None:
        self.conn.execute(
            "UPDATE service_nodes SET last_heartbeat = CURRENT_TIMESTAMP, status = ? WHERE node_id = ?;",
            (status, node_id)
        )

    def set_status(self, node_id: str, status: str) -> None:
        self.conn.execute("UPDATE service_nodes SET status = ? WHERE node_id = ?;", (status, node_id))

    def update_epoch(self, node_id: str, epoch: int, active_key: str | None = None) -> None:
        if active_key:
            self.conn.execute(
                "UPDATE service_nodes SET current_epoch = ?, active_key_version = ? WHERE node_id = ?;",
                (epoch, active_key, node_id)
            )
        else:
            self.conn.execute(
                "UPDATE service_nodes SET current_epoch = ? WHERE node_id = ?;",
                (epoch, node_id)
            )

    def get_node(self, node_id: str) -> dict[str, Any] | None:
        cursor = self.conn.execute("SELECT * FROM service_nodes WHERE node_id = ?;", (node_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def list_nodes(self) -> list[dict[str, Any]]:
        cursor = self.conn.execute("SELECT * FROM service_nodes ORDER BY node_id ASC;")
        return [dict(row) for row in cursor.fetchall()]


class ClusterEpochRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def get_current_epoch(self) -> int:
        cursor = self.conn.execute("SELECT MAX(epoch_counter) as max_epoch FROM cluster_epoch;")
        row = cursor.fetchone()
        if row and row["max_epoch"] is not None:
            return int(row["max_epoch"])
        return 1

    def advance_epoch(self, revocation_hash: str) -> int:
        curr = self.get_current_epoch()
        next_epoch = curr + 1
        self.conn.execute(
            "INSERT INTO cluster_epoch (epoch_counter, revocation_hash, committed_at) "
            "VALUES (?, ?, CURRENT_TIMESTAMP);",
            (next_epoch, revocation_hash)
        )
        return next_epoch

    def init_epoch(self, initial_epoch: int = 1, revocation_hash: str = "epoch-0-genesis") -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO cluster_epoch (epoch_counter, revocation_hash, committed_at) "
            "VALUES (?, ?, CURRENT_TIMESTAMP);",
            (initial_epoch, revocation_hash)
        )

    def get_latest_checkpoint(self) -> dict[str, Any] | None:
        cursor = self.conn.execute(
            "SELECT * FROM cluster_epoch ORDER BY epoch_counter DESC LIMIT 1;"
        )
        row = cursor.fetchone()
        return dict(row) if row else None


class AuditCheckpointRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def create_checkpoint(self, checkpoint_id: str, sequence_up_to: int,
                          cumulative_hash: str, checkpoint_hmac: str) -> None:
        self.conn.execute(
            "INSERT INTO audit_checkpoints (checkpoint_id, sequence_up_to, cumulative_hash, checkpoint_hmac, created_at) "
            "VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP) "
            "ON CONFLICT(checkpoint_id) DO UPDATE SET sequence_up_to = excluded.sequence_up_to, "
            "cumulative_hash = excluded.cumulative_hash, checkpoint_hmac = excluded.checkpoint_hmac;",
            (checkpoint_id, sequence_up_to, cumulative_hash, checkpoint_hmac)
        )

    def get_latest_checkpoint(self) -> dict[str, Any] | None:
        cursor = self.conn.execute(
            "SELECT * FROM audit_checkpoints ORDER BY sequence_up_to DESC LIMIT 1;"
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_checkpoint(self, checkpoint_id: str) -> dict[str, Any] | None:
        cursor = self.conn.execute(
            "SELECT * FROM audit_checkpoints WHERE checkpoint_id = ?;", (checkpoint_id,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def list_checkpoints(self) -> list[dict[str, Any]]:
        cursor = self.conn.execute("SELECT * FROM audit_checkpoints ORDER BY sequence_up_to ASC;")
        return [dict(row) for row in cursor.fetchall()]


class AuditRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def record(self, request_id: str, event_time_utc: str, actor_id: str, op: str,
               asset_id: str | None, decision: str, rule: str, entry_hash: str,
               prev_hash: str = "0000000000000000000000000000000000000000000000000000000000000000") -> None:
        self.conn.execute(
            "INSERT INTO audit_events (request_id, event_time_utc, actor_id, op, asset_id, decision, rule, prev_hash, entry_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(request_id) DO NOTHING;",  # Immutable audit: preserve original decision
            (request_id, event_time_utc, actor_id, op, asset_id, decision, rule, prev_hash, entry_hash)
        )

    def get(self, request_id: str) -> dict[str, Any] | None:
        cursor = self.conn.execute(
            "SELECT sequence_num, request_id, decision, rule, event_time_utc, actor_id, op, asset_id, prev_hash, entry_hash "
            "FROM audit_events WHERE request_id = ?;",
            (request_id,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_last_entry(self) -> dict[str, Any] | None:
        cursor = self.conn.execute(
            "SELECT sequence_num, request_id, decision, rule, event_time_utc, actor_id, op, asset_id, prev_hash, entry_hash "
            "FROM audit_events ORDER BY sequence_num DESC LIMIT 1;"
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_chain(self, start_seq: int = 1, limit: int | None = None) -> list[dict[str, Any]]:
        query = "SELECT sequence_num, request_id, decision, rule, event_time_utc, actor_id, op, asset_id, prev_hash, entry_hash " \
                "FROM audit_events WHERE sequence_num >= ? ORDER BY sequence_num ASC"
        if limit:
            query += f" LIMIT {int(limit)}"
        cursor = self.conn.execute(query, (start_seq,))
        return [dict(row) for row in cursor.fetchall()]

    def count(self) -> int:
        cursor = self.conn.execute("SELECT COUNT(*) as cnt FROM audit_events;")
        return cursor.fetchone()["cnt"]


# ============================================================================
# Phase 1.3 Repositories: Telemetry, Approvals, Detection, Messaging, Outbox
# ============================================================================

class TelemetryRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def insert(self, event_id: str, event_time_utc: str, received_time_utc: str,
               source_clock_offset_ms: int, corrected_time_utc: str, actor: str,
               source_service: str, target_service: str, action: str,
               role_before: str | None, role_after: str | None, outcome: str,
               approval_id: str | None, session_id: str | None, correlation_id: str | None,
               is_practice: bool = False) -> None:
        self.conn.execute(
            "INSERT INTO telemetry_events ("
            "  event_id, event_time_utc, received_time_utc, source_clock_offset_ms, "
            "  corrected_time_utc, actor, source_service, target_service, action, "
            "  role_before, role_after, outcome, approval_id, session_id, correlation_id, is_practice"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(event_id) DO UPDATE SET "
            "  corrected_time_utc = excluded.corrected_time_utc, "
            "  outcome = excluded.outcome;",
            (
                event_id, event_time_utc, received_time_utc, source_clock_offset_ms,
                corrected_time_utc, actor, source_service, target_service, action,
                role_before, role_after, outcome, approval_id, session_id, correlation_id,
                1 if is_practice else 0
            )
        )

    def get(self, event_id: str) -> dict[str, Any] | None:
        cursor = self.conn.execute("SELECT * FROM telemetry_events WHERE event_id = ?;", (event_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def list_all(self, order_by_corrected: bool = True) -> list[dict[str, Any]]:
        order = "ORDER BY corrected_time_utc ASC, event_id ASC" if order_by_corrected else "ORDER BY event_time_utc ASC"
        cursor = self.conn.execute(f"SELECT * FROM telemetry_events {order};")
        return [dict(row) for row in cursor.fetchall()]

    def list_by_session(self, session_id: str) -> list[dict[str, Any]]:
        cursor = self.conn.execute(
            "SELECT * FROM telemetry_events WHERE session_id = ? ORDER BY corrected_time_utc ASC;",
            (session_id,)
        )
        return [dict(row) for row in cursor.fetchall()]

    def list_by_actor(self, actor: str) -> list[dict[str, Any]]:
        cursor = self.conn.execute(
            "SELECT * FROM telemetry_events WHERE actor = ? ORDER BY corrected_time_utc ASC;",
            (actor,)
        )
        return [dict(row) for row in cursor.fetchall()]


class ApprovalRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def insert(self, approval_id: str, approved_by: str, subject: str,
               operation: str, role: str, scope_json: str, valid_from_utc: str,
               valid_until_utc: str | None = None, effective_at_utc: str | None = None) -> None:
        self.conn.execute(
            "INSERT INTO approvals ("
            "  approval_id, approved_by, subject, operation, role, scope_json, "
            "  valid_from_utc, valid_until_utc, effective_at_utc"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(approval_id) DO UPDATE SET "
            "  valid_until_utc = excluded.valid_until_utc, "
            "  effective_at_utc = excluded.effective_at_utc;",
            (
                approval_id, approved_by, subject, operation, role, scope_json,
                valid_from_utc, valid_until_utc, effective_at_utc
            )
        )

    def get(self, approval_id: str) -> dict[str, Any] | None:
        cursor = self.conn.execute("SELECT * FROM approvals WHERE approval_id = ?;", (approval_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def list_for_subject(self, subject: str) -> list[dict[str, Any]]:
        cursor = self.conn.execute(
            "SELECT * FROM approvals WHERE subject = ? ORDER BY valid_from_utc ASC;",
            (subject,)
        )
        return [dict(row) for row in cursor.fetchall()]

    def list_all(self) -> list[dict[str, Any]]:
        cursor = self.conn.execute("SELECT * FROM approvals ORDER BY valid_from_utc ASC;")
        return [dict(row) for row in cursor.fetchall()]


class ServiceGraphRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def add_edge(self, source_service: str, target_service: str,
                 is_expected: bool = True, allowed_roles_json: str | None = None) -> None:
        self.conn.execute(
            "INSERT INTO service_edges (source_service, target_service, is_expected, allowed_roles_json) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(source_service, target_service) DO UPDATE SET "
            "  is_expected = excluded.is_expected, "
            "  allowed_roles_json = excluded.allowed_roles_json;",
            (source_service, target_service, 1 if is_expected else 0, allowed_roles_json)
        )

    def is_edge_expected(self, source_service: str, target_service: str) -> bool:
        cursor = self.conn.execute(
            "SELECT is_expected FROM service_edges WHERE source_service = ? AND target_service = ?;",
            (source_service, target_service)
        )
        row = cursor.fetchone()
        if row is None:
            # If not configured, default policy: edge between distinct unknown services is unexpected
            return False
        return bool(row["is_expected"])

    def list_edges(self) -> list[dict[str, Any]]:
        cursor = self.conn.execute("SELECT * FROM service_edges ORDER BY source_service, target_service;")
        return [dict(row) for row in cursor.fetchall()]


class ThreatIncidentRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def record_incident(self, incident_id: str, rule_id: str, incident_type: str,
                        actor_id: str, severity: str, explanation: str,
                        evidence_event_ids_json: str, status: str = "open") -> None:
        self.conn.execute(
            "INSERT INTO threat_incidents ("
            "  incident_id, rule_id, incident_type, actor_id, severity, explanation, status, evidence_event_ids_json"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(incident_id) DO UPDATE SET "
            "  explanation = excluded.explanation, status = excluded.status;",
            (incident_id, rule_id, incident_type, actor_id, severity, explanation, status, evidence_event_ids_json)
        )

    def get(self, incident_id: str) -> dict[str, Any] | None:
        cursor = self.conn.execute("SELECT * FROM threat_incidents WHERE incident_id = ?;", (incident_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def list_all(self) -> list[dict[str, Any]]:
        cursor = self.conn.execute("SELECT * FROM threat_incidents ORDER BY created_at ASC;")
        return [dict(row) for row in cursor.fetchall()]

    def list_by_type(self, incident_type: str) -> list[dict[str, Any]]:
        cursor = self.conn.execute("SELECT * FROM threat_incidents WHERE incident_type = ?;", (incident_type,))
        return [dict(row) for row in cursor.fetchall()]


class MessageRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def store_message(self, message_id: str, session_id: str, sender_id: str,
                      sender_device: str, recipient_id: str, recipient_device: str,
                      sequence_num: int, nonce: bytes, ciphertext: bytes, mac: bytes,
                      status: str = "delivered") -> None:
        self.conn.execute(
            "INSERT INTO messages ("
            "  message_id, session_id, sender_id, sender_device, recipient_id, recipient_device, "
            "  sequence_num, nonce, ciphertext, mac, status"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            (
                message_id, session_id, sender_id, sender_device, recipient_id, recipient_device,
                sequence_num, nonce, ciphertext, mac, status
            )
        )

    def get(self, message_id: str) -> dict[str, Any] | None:
        cursor = self.conn.execute("SELECT * FROM messages WHERE message_id = ?;", (message_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def list_by_session(self, session_id: str) -> list[dict[str, Any]]:
        cursor = self.conn.execute(
            "SELECT * FROM messages WHERE session_id = ? ORDER BY sequence_num ASC;",
            (session_id,)
        )
        return [dict(row) for row in cursor.fetchall()]


class ReplayRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def record_seen(self, message_id: str, session_id: str, sequence_num: int) -> bool:
        """Attempt to insert message into replay cache. Returns True if new, False if replay."""
        try:
            self.conn.execute(
                "INSERT INTO replay_cache (message_id, session_id, sequence_num) VALUES (?, ?, ?);",
                (message_id, session_id, sequence_num)
            )
            return True
        except sqlite3.IntegrityError:
            return False

    def is_seen(self, message_id: str) -> bool:
        cursor = self.conn.execute("SELECT 1 FROM replay_cache WHERE message_id = ?;", (message_id,))
        return cursor.fetchone() is not None


class OfflineOutboxRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def enqueue(self, outbox_id: str, actor_id: str, device_id: str,
                recipient_id: str, payload_ciphertext: bytes, nonce: bytes) -> None:
        self.conn.execute(
            "INSERT INTO offline_outbox ("
            "  outbox_id, actor_id, device_id, recipient_id, payload_ciphertext, nonce, status, attempts"
            ") VALUES (?, ?, ?, ?, ?, ?, 'queued', 0);",
            (outbox_id, actor_id, device_id, recipient_id, payload_ciphertext, nonce)
        )

    def mark_delivered(self, outbox_id: str) -> None:
        self.conn.execute(
            "UPDATE offline_outbox SET status = 'delivered', delivered_at = CURRENT_TIMESTAMP WHERE outbox_id = ?;",
            (outbox_id,)
        )

    def claim_pending(self, outbox_id: str) -> bool:
        cursor = self.conn.execute(
            "UPDATE offline_outbox SET status = 'sending' WHERE outbox_id = ? AND status = 'queued';",
            (outbox_id,)
        )
        return cursor.rowcount > 0

    def release_claim(self, outbox_id: str) -> None:
        self.conn.execute(
            "UPDATE offline_outbox SET status = 'queued' WHERE outbox_id = ? AND status = 'sending';",
            (outbox_id,)
        )

    def increment_attempts(self, outbox_id: str) -> None:
        self.conn.execute(
            "UPDATE offline_outbox SET attempts = attempts + 1 WHERE outbox_id = ?;",
            (outbox_id,)
        )

    def list_pending(self, actor_id: str | None = None) -> list[dict[str, Any]]:
        if actor_id:
            cursor = self.conn.execute(
                "SELECT * FROM offline_outbox WHERE actor_id = ? AND status IN ('queued', 'sending') ORDER BY created_at ASC;",
                (actor_id,)
            )
        else:
            cursor = self.conn.execute(
                "SELECT * FROM offline_outbox WHERE status IN ('queued', 'sending') ORDER BY created_at ASC;"
            )
        return [dict(row) for row in cursor.fetchall()]
