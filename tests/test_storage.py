"""Tests for database persistence, SQLite WAL, and isolation (DB01 - DB08)."""
import os
from pathlib import Path
import tempfile
import unittest

from quantumvault.core.errors import StateError
from quantumvault.storage.db import get_connection, init_db, reset_state, transaction
from quantumvault.storage.repositories import (
    AppStateRepository,
    AssetRepository,
    IdentityRepository,
    KeyVersionRepository,
    RevocationRepository,
    TelemetryRepository,
)


class TestStorage(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.conn = get_connection(self.db_path)
        init_db(self.conn)

    def tearDown(self):
        self.conn.close()
        self.temp_dir.cleanup()

    def test_db01_clean_initialization(self):
        """DB01: Schema initializes all required tables and indexes."""
        cursor = self.conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row["name"] for row in cursor.fetchall()}
        self.assertTrue({"app_state", "identities", "assets", "revocations", "audit_events"}.issubset(tables))

    def test_db02_state_survives_process_restart(self):
        """DB02: Committed state survives connection closing and reopening."""
        app_repo = AppStateRepository(self.conn)
        with transaction(self.conn):
            app_repo.set("epoch", "42")
        
        self.conn.close()
        
        # Reopen connection
        new_conn = get_connection(self.db_path)
        new_repo = AppStateRepository(new_conn)
        self.assertEqual(new_repo.get("epoch"), "42")
        new_conn.close()

    def test_db03_isolated_state_directories(self):
        """DB03: Two separate database files remain completely isolated."""
        with tempfile.TemporaryDirectory() as other_dir:
            other_path = Path(other_dir) / "other.db"
            other_conn = get_connection(other_path)
            init_db(other_conn)
            
            repo1 = IdentityRepository(self.conn)
            repo2 = IdentityRepository(other_conn)
            
            with transaction(self.conn):
                repo1.upsert("user-1", status="active")
            with transaction(other_conn):
                repo2.upsert("user-2", status="active")
            
            self.assertIsNotNone(repo1.get("user-1"))
            self.assertIsNone(repo1.get("user-2"))
            self.assertIsNone(repo2.get("user-1"))
            self.assertIsNotNone(repo2.get("user-2"))
            other_conn.close()

    def test_db04_reset_state_clears_application_tables(self):
        """DB04: reset_state cleans tables atomically."""
        app_repo = AppStateRepository(self.conn)
        ident_repo = IdentityRepository(self.conn)
        with transaction(self.conn):
            app_repo.set("marker", "test")
            ident_repo.upsert("actor-x")
        
        with transaction(self.conn):
            reset_state(self.conn)
        
        self.assertIsNone(app_repo.get("marker"))
        self.assertIsNone(ident_repo.get("actor-x"))

    def test_db05_revocation_persists(self):
        """DB05: Revocations table persists and queries accurately."""
        rev_repo = RevocationRepository(self.conn)
        with transaction(self.conn):
            rev_repo.revoke("malicious-actor", reason="device_theft")
        
        self.assertTrue(rev_repo.is_revoked("malicious-actor"))
        self.assertFalse(rev_repo.is_revoked("innocent-actor"))

    def test_db06_transaction_rollback_on_failure(self):
        """DB06: Unhandled exception in transaction rolls back all pending changes."""
        ident_repo = IdentityRepository(self.conn)
        try:
            with transaction(self.conn):
                ident_repo.upsert("temp-actor")
                raise RuntimeError("Simulated mid-transaction failure")
        except RuntimeError:
            pass
        
        self.assertIsNone(ident_repo.get("temp-actor"))

    def test_db07_parameterized_sql_handles_special_characters(self):
        """DB07: SQL queries handle injection characters, unicode, and quotes."""
        ident_repo = IdentityRepository(self.conn)
        special_actors = [
            "user' OR '1'='1",
            "actor--DROP TABLE assets;",
            "user\x00nullbyte",
            "🔥unicode-actor🔥"
        ]
        with transaction(self.conn):
            for actor in special_actors:
                ident_repo.upsert(actor, status="active")
        
        for actor in special_actors:
            res = ident_repo.get(actor)
            self.assertIsNotNone(res)
            self.assertEqual(res["actor_id"], actor)

    def test_db08_key_version_field_whitelist_rejects_injection(self):
        """DB08: KeyVersionRepository strictly whitelists fields and rejects injection/unknown columns."""
        repo = KeyVersionRepository(self.conn)
        repo.create_version("v1", b"enc-key", b"nonce-123", status="pre_active")

        # Valid update
        repo.update_status("v1", "active", activated_at="2026-01-01T00:00:00Z")
        rec = repo.get_version("v1")
        self.assertIsNotNone(rec)
        self.assertEqual(rec["status"], "active")
        self.assertEqual(rec["activated_at"], "2026-01-01T00:00:00Z")

        # Unknown column
        with self.assertRaises(ValueError) as cm:
            repo.update_fields("v1", {"non_existent_column": "value"})
        self.assertIn("Unknown or disallowed field", str(cm.exception))

        # Injection string in field name
        with self.assertRaises(ValueError) as cm:
            repo.update_fields("v1", {"status = 'hacked'--": "value"})
        self.assertIn("Unknown or disallowed field", str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            repo.update_status("v1", "active", **{"injected_col; DROP TABLE key_versions;--": "val"})
        self.assertIn("Unknown or disallowed field", str(cm.exception))

    def test_db09_telemetry_order_whitelist_rejects_injection(self):
        """DB09: TelemetryRepository strictly whitelists order fields and rejects SQL injection."""
        repo = TelemetryRepository(self.conn)
        repo.insert(
            event_id="evt-001",
            event_time_utc="2026-01-15T09:00:00.000Z",
            received_time_utc="2026-01-15T09:00:01.000Z",
            source_clock_offset_ms=0,
            corrected_time_utc="2026-01-15T09:00:00.000Z",
            actor="test-actor",
            source_service="portal",
            target_service="identity",
            action="login",
            outcome="success"
        )

        # Valid order_by values
        events_corr = repo.list_all(order_by="corrected")
        self.assertEqual(len(events_corr), 1)
        events_time = repo.list_all(order_by="event_time")
        self.assertEqual(len(events_time), 1)

        # Unknown order column
        with self.assertRaises(ValueError) as cm:
            repo.list_all(order_by="invalid_column")
        self.assertIn("Unknown or disallowed order field", str(cm.exception))

        # SQL injection attempt in order string
        with self.assertRaises(ValueError) as cm:
            repo.list_all(order_by="event_time_utc; DROP TABLE telemetry_events;--")
        self.assertIn("Unknown or disallowed order field", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
