"""Group 10: Secret Leakage Prevention and Audit Log Injection Tests."""
from __future__ import annotations

import io
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from quantumvault.audit.logger import AuditLogger
from quantumvault.audit.verifier import AuditLogVerifier
from tests_round2.helpers import open_service
from quantumvault.config import get_db_path
from quantumvault.storage.db import get_connection


class TestLeakageAndAuditInjection(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp_dir.name)
        self.secret_marker = "SUPER_SECRET_KEY_MATERIAL_MARKER_xyz789"
        with open_service(state_dir=self.state_dir) as service:
            service.setup(
                owners={"doc-secret": "eve"},
                contents={"doc-secret": "Super Secret Plaintext Document"},
                disabled=[],
                key_material=self.secret_marker
            )

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_leak01_key_material_never_in_audit_log_or_tables(self):
        """Secret key_material marker must never be written in plaintext to audit tables or DB."""
        conn = get_connection(get_db_path(self.state_dir))
        cursor = conn.execute("SELECT * FROM audit_events;")
        rows = [dict(r) for r in cursor.fetchall()]
        for r in rows:
            for k, v in r.items():
                self.assertNotIn(
                    self.secret_marker, str(v),
                    f"CRITICAL: Plaintext secret marker leaked into audit column '{k}'!"
                )
        conn.close()

    def test_leak02_raw_db_file_scan_for_secret_marker(self):
        """Raw SQLite file scan confirms master key material is not stored in plaintext."""
        db_file = get_db_path(self.state_dir)
        with open(db_file, "rb") as f:
            content = f.read()
        self.assertNotIn(
            self.secret_marker.encode("utf-8"), content,
            "CRITICAL: Plaintext secret marker found unencrypted in database binary!"
        )

    def test_inject01_audit_log_newline_and_json_injection(self):
        """Attacker cannot forge audit log entries using newline or JSON delimiters."""
        conn = get_connection(get_db_path(self.state_dir))
        logger = AuditLogger(conn)
        verifier = AuditLogVerifier(conn)

        malicious_actors = [
            'eve\n{"decision":"allow","rule":"forged"}\n',
            'eve\r\nprev_hash=00000000000000000000000000000000',
            'eve", "decision": "allow", "entry_hash": "abc',
            'eve\x00malicious'
        ]

        for idx, mal_actor in enumerate(malicious_actors):
            logger.log_decision(
                request_id=f"req-inj-{idx}",
                actor_id=mal_actor,
                op="read",
                asset_id="doc-secret",
                decision="deny",
                rule="suspicious_input"
            )

        # Hash chain verification must remain cryptographically valid and tamper-evident
        res = verifier.verify()
        self.assertEqual(res["status"], "valid", f"Audit chain verification failed: {res}")
        conn.close()


if __name__ == "__main__":
    unittest.main()
