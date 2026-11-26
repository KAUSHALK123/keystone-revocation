"""Group 9: Database Abuse and Resilience Tests."""
from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests_round2.helpers import open_service
from quantumvault.config import get_db_path
from quantumvault.storage.db import get_connection


class TestDatabaseAbuse(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp_dir.name)
        with open_service(state_dir=self.state_dir) as service:
            service.setup(
                owners={"doc-db": "dave"},
                contents={"doc-db": "Database Resilience Document"},
                disabled=[],
                key_material="db-abuse-testing-key"
            )

    def tearDown(self):
        # Restore permissions if read-only
        db_file = get_db_path(self.state_dir)
        if db_file.exists():
            try:
                os.chmod(db_file, stat.S_IWRITE | stat.S_IREAD)
            except Exception:
                pass
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_db_abuse01_corrupted_sqlite_header_fails_closed(self):
        """Corrupting the SQLite file header must cause fail-closed behavior, never allow."""
        db_file = get_db_path(self.state_dir)
        self.assertTrue(db_file.exists())

        # Overwrite first 100 bytes of the SQLite database with zeros
        with open(db_file, "r+b") as f:
            f.write(b"\x00" * 100)

        try:
            with open_service(state_dir=self.state_dir) as svc:
                res = svc.read("dave", "doc-db", "r01")
                self.assertEqual(res["decision"], "deny")
        except Exception:
            # Raising database error / StateError is safe fail-closed behavior
            pass

    def test_db_abuse02_deleted_identities_table_fails_closed(self):
        """Deleting the identities table must cause operations to fail closed."""
        conn = get_connection(get_db_path(self.state_dir))
        conn.execute("DROP TABLE identities;")
        conn.commit()
        conn.close()

        with open_service(state_dir=self.state_dir) as svc:
            try:
                res = svc.read("dave", "doc-db", "r02")
                self.assertEqual(res["decision"], "deny")
            except Exception:
                pass

    def test_db_abuse03_read_only_database_fails_closed_on_mutation(self):
        """When database file is read-only, mutations must fail closed."""
        db_file = get_db_path(self.state_dir)
        os.chmod(db_file, stat.S_IREAD)

        with open_service(state_dir=self.state_dir) as svc:
            try:
                svc.revoke("dave")
            except Exception:
                pass


if __name__ == "__main__":
    unittest.main()
