"""Database connection and lifecycle management for QuantumVault."""
from contextlib import contextmanager
from pathlib import Path
import sqlite3
import time
from typing import Generator

from quantumvault.config import get_db_path, get_state_dir
from quantumvault.core.errors import StateError

SCHEMA_PATH = Path(__file__).parent / "schema.sql"
SCHEMA_VERSION = 2


def get_connection(db_path: Path | None = None) -> sqlite3.Connection:
    """Open a configured SQLite connection with foreign keys and WAL mode."""
    target_path = db_path or get_db_path()
    try:
        conn = sqlite3.connect(
            str(target_path),
            timeout=10.0,
            check_same_thread=False,
            isolation_level=None  # Explicit autocommit mode; manage transactions manually
        )
        conn.row_factory = sqlite3.Row
        
        # Configure robust pragmas
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA busy_timeout = 10000;")
        try:
            conn.execute("PRAGMA journal_mode = WAL;")
        except sqlite3.OperationalError:
            pass  # Fall back to default journal mode on filesystems without shared memory
        try:
            conn.execute("PRAGMA synchronous = FULL;")
        except sqlite3.OperationalError:
            pass
            
        return conn
    except sqlite3.Error as e:
        raise StateError(f"Failed to connect to database at {target_path}: {e}") from e


def init_db(conn: sqlite3.Connection) -> None:
    """Execute DDL schema idempotently with version tracking and legacy auto-migration."""
    try:
        cur = conn.cursor()
        current_ver = cur.execute("PRAGMA user_version;").fetchone()[0]

        # Fast path when schema is already at current version and core tables exist
        if current_ver >= SCHEMA_VERSION:
            existing = cur.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('identities', 'assets', 'audit_events', 'schema_migrations');"
            ).fetchone()[0]
            if existing == 4:
                return

        # Check for legacy tables and migrate missing columns if present
        cur.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='assets'")
        row = cur.fetchone()
        if row and "key_version" not in row[0]:
            try:
                conn.execute("ALTER TABLE assets ADD COLUMN key_version TEXT NOT NULL DEFAULT 'v1';")
            except sqlite3.OperationalError:
                pass

        # Check audit_events table for sequence_num column
        cur.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='audit_events'")
        row = cur.fetchone()
        if row and "sequence_num" not in row[0]:
            conn.execute("DROP TABLE IF EXISTS audit_events_old;")
            conn.execute("ALTER TABLE audit_events RENAME TO audit_events_old;")

        schema_sql = SCHEMA_PATH.read_text(encoding="utf-8")
        conn.executescript(schema_sql)

        # Ensure schema_migrations tracking table exists
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "  version INTEGER PRIMARY KEY,"
            "  description TEXT NOT NULL,"
            "  applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
            ");"
        )

        # Migrate audit_events data if old table was renamed
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_events_old'")
        if cur.fetchone():
            conn.execute("""
                INSERT OR IGNORE INTO audit_events 
                (request_id, event_time_utc, actor_id, op, asset_id, decision, rule, entry_hash)
                SELECT request_id, event_time_utc, actor_id, op, asset_id, decision, rule, entry_hash
                FROM audit_events_old;
            """)
            conn.execute("DROP TABLE audit_events_old;")

        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations (version, description) VALUES (?, ?);",
            (SCHEMA_VERSION, "QuantumVault Phase 2 hardened schema with legacy migration support")
        )
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION};")

    except (sqlite3.Error, OSError) as e:
        raise StateError(f"Database schema initialization failed: {e}") from e


def verify_db_integrity(conn: sqlite3.Connection) -> bool:
    """Verify SQLite physical and index integrity via PRAGMA integrity_check."""
    try:
        row = conn.execute("PRAGMA integrity_check;").fetchone()
        return bool(row and str(row[0]).lower() == "ok")
    except sqlite3.Error:
        return False


def reset_state(conn: sqlite3.Connection) -> None:
    """Atomically reset application state for clean setup invocations."""
    try:
        conn.execute("DELETE FROM offline_outbox;")
        conn.execute("DELETE FROM replay_cache;")
        conn.execute("DELETE FROM messages;")
        conn.execute("DELETE FROM threat_incidents;")
        conn.execute("DELETE FROM service_edges;")
        conn.execute("DELETE FROM approvals;")
        conn.execute("DELETE FROM telemetry_events;")
        conn.execute("DELETE FROM recovery_credentials;")
        conn.execute("DELETE FROM devices;")
        conn.execute("DELETE FROM service_nodes;")
        conn.execute("DELETE FROM cluster_epoch;")
        conn.execute("DELETE FROM audit_checkpoints;")
        conn.execute("DELETE FROM key_versions;")
        conn.execute("DELETE FROM assets;")
        conn.execute("DELETE FROM revocations;")
        conn.execute("DELETE FROM identities;")
        conn.execute("DELETE FROM audit_events;")
        conn.execute("DELETE FROM app_state;")
        try:
            conn.execute("DELETE FROM sqlite_sequence;")
        except sqlite3.OperationalError:
            pass
    except sqlite3.Error as e:
        raise StateError(f"Failed to reset application state: {e}") from e


@contextmanager
def transaction(conn: sqlite3.Connection, max_retries: int = 5) -> Generator[sqlite3.Connection, None, None]:
    """Provide an atomic transaction scope with automatic rollback on error.
    Supports re-entrant / nested transaction blocks safely and retries on transient locks."""
    nested = conn.in_transaction
    if not nested:
        for attempt in range(max_retries):
            try:
                conn.execute("BEGIN IMMEDIATE;")
                break
            except sqlite3.OperationalError as e:
                if ("locked" in str(e).lower() or "busy" in str(e).lower()) and attempt < max_retries - 1:
                    time.sleep(0.02 * (2 ** attempt))
                    continue
                raise
    try:
        yield conn
        if not nested:
            conn.execute("COMMIT;")
    except Exception:
        if not nested:
            try:
                conn.execute("ROLLBACK;")
            except sqlite3.Error:
                pass
        raise
