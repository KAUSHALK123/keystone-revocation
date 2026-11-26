-- QuantumVault Core Persistence Schema (Phase 1.1 + Phase 1.2 Extensions)

PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS app_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS identities (
    actor_id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK(status IN ('active', 'disabled')),
    role TEXT NOT NULL DEFAULT 'viewer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_identities_status ON identities(status);

CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL REFERENCES identities(actor_id) ON DELETE CASCADE,
    public_key_b64 TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active', 'revoked', 'pending')),
    enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_devices_actor ON devices(actor_id);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);

CREATE TABLE IF NOT EXISTS recovery_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id TEXT NOT NULL REFERENCES identities(actor_id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL UNIQUE,
    salt TEXT NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_recovery_actor ON recovery_credentials(actor_id);
CREATE INDEX IF NOT EXISTS idx_recovery_code_hash ON recovery_credentials(code_hash);

CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    owner_actor_id TEXT NOT NULL REFERENCES identities(actor_id) ON DELETE CASCADE,
    encrypted_body BLOB NOT NULL,
    nonce BLOB NOT NULL,
    key_version TEXT NOT NULL DEFAULT 'v1',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_assets_owner ON assets(owner_actor_id);

CREATE TABLE IF NOT EXISTS revocations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id TEXT NOT NULL,
    entity_type TEXT NOT NULL DEFAULT 'actor',
    reason TEXT,
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(actor_id, entity_type)
);

CREATE INDEX IF NOT EXISTS idx_revocations_actor ON revocations(actor_id);

CREATE TABLE IF NOT EXISTS key_versions (
    version_id TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL DEFAULT 'AES-256-GCM',
    encrypted_key_bytes BLOB NOT NULL,
    nonce BLOB NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pre_active', 'active', 'grace_period', 'retired')),
    activated_at TIMESTAMP,
    cutoff_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_key_versions_status ON key_versions(status);

CREATE TABLE IF NOT EXISTS service_nodes (
    node_id TEXT PRIMARY KEY,
    address TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('online', 'offline', 'degraded')),
    last_heartbeat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    current_epoch INTEGER NOT NULL DEFAULT 1,
    active_key_version TEXT NOT NULL DEFAULT 'v1'
);

CREATE TABLE IF NOT EXISTS cluster_epoch (
    epoch_id INTEGER PRIMARY KEY AUTOINCREMENT,
    epoch_counter INTEGER NOT NULL UNIQUE,
    revocation_hash TEXT NOT NULL,
    committed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    sequence_up_to INTEGER NOT NULL,
    cumulative_hash TEXT NOT NULL,
    checkpoint_hmac TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_events (
    sequence_num INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT UNIQUE,
    event_time_utc TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    op TEXT NOT NULL,
    asset_id TEXT,
    decision TEXT NOT NULL CHECK(decision IN ('allow', 'deny')),
    rule TEXT NOT NULL,
    prev_hash TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
    entry_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_events(event_time_utc);
CREATE INDEX IF NOT EXISTS idx_audit_seq ON audit_events(sequence_num);

-- ============================================================================
-- Phase 1.3 Telemetry, Threat Detection, and Forward-Secure Messaging Tables
-- ============================================================================

CREATE TABLE IF NOT EXISTS telemetry_events (
    event_id TEXT PRIMARY KEY,
    event_time_utc TEXT NOT NULL,
    received_time_utc TEXT NOT NULL,
    source_clock_offset_ms INTEGER NOT NULL DEFAULT 0,
    corrected_time_utc TEXT NOT NULL,
    actor TEXT NOT NULL,
    source_service TEXT NOT NULL,
    target_service TEXT NOT NULL,
    action TEXT NOT NULL,
    role_before TEXT,
    role_after TEXT,
    outcome TEXT NOT NULL,
    approval_id TEXT,
    session_id TEXT,
    correlation_id TEXT,
    is_practice BOOLEAN NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_telemetry_actor ON telemetry_events(actor);
CREATE INDEX IF NOT EXISTS idx_telemetry_corr ON telemetry_events(correlation_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_sess ON telemetry_events(session_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_time ON telemetry_events(corrected_time_utc);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    approved_by TEXT NOT NULL,
    subject TEXT NOT NULL,
    operation TEXT NOT NULL,
    role TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    valid_from_utc TEXT NOT NULL,
    valid_until_utc TEXT,
    effective_at_utc TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_approvals_subject ON approvals(subject);

CREATE TABLE IF NOT EXISTS service_edges (
    source_service TEXT NOT NULL,
    target_service TEXT NOT NULL,
    is_expected BOOLEAN NOT NULL DEFAULT 1,
    allowed_roles_json TEXT,
    PRIMARY KEY (source_service, target_service)
);

CREATE TABLE IF NOT EXISTS threat_incidents (
    incident_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    incident_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high', 'critical')),
    explanation TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'investigating', 'resolved', 'dismissed')),
    evidence_event_ids_json TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_incidents_actor ON threat_incidents(actor_id);
CREATE INDEX IF NOT EXISTS idx_incidents_type ON threat_incidents(incident_type);

CREATE TABLE IF NOT EXISTS messages (
    message_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    sender_device TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    recipient_device TEXT NOT NULL,
    sequence_num INTEGER NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    mac BLOB NOT NULL,
    status TEXT NOT NULL DEFAULT 'delivered' CHECK(status IN ('delivered', 'dropped', 'tampered')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id);
CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id);

CREATE TABLE IF NOT EXISTS replay_cache (
    message_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    sequence_num INTEGER NOT NULL,
    seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_replay_session ON replay_cache(session_id);

CREATE TABLE IF NOT EXISTS offline_outbox (
    outbox_id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    payload_ciphertext BLOB NOT NULL,
    nonce BLOB NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued', 'sending', 'delivered', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    delivered_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_outbox_actor ON offline_outbox(actor_id);
CREATE INDEX IF NOT EXISTS idx_outbox_status ON offline_outbox(status);
