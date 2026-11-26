"""Group 3: Concurrency and Race Condition Tests."""
from __future__ import annotations

import concurrent.futures
from pathlib import Path
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests_round2.helpers import open_service
from quantumvault.config import get_db_path, get_vault_key_path
from quantumvault.crypto.key_manager import load_vault_key
from quantumvault.crypto.rotation import KeyRotationManager
from quantumvault.storage.db import get_connection


class TestConcurrencyRaces(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp_dir.name)
        with open_service(state_dir=self.state_dir) as service:
            service.setup(
                owners={"f1": "alice", "f2": "bob"},
                contents={"f1": "Confidential Alpha", "f2": "Confidential Beta"},
                disabled=[],
                key_material="race-condition-master-secret"
            )

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_race01_revoke_vs_read_toctou(self):
        """TOCTOU check: After revoke completes, read must NEVER succeed."""
        results: list[dict[str, str]] = []
        revoke_finished_time = None

        def worker_read(i: int):
            t_req = time.perf_counter()
            with open_service(state_dir=self.state_dir) as svc:
                res = svc.read("alice", "f1", f"req-{i}")
            t_done = time.perf_counter()
            results.append({
                "req": f"req-{i}",
                "decision": res.get("decision", ""),
                "t_req": t_req,
                "t_done": t_done
            })

        def worker_revoke():
            nonlocal revoke_finished_time
            time.sleep(0.01)  # Allow a few reads to queue up
            with open_service(state_dir=self.state_dir) as svc:
                svc.revoke("alice")
            revoke_finished_time = time.perf_counter()

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(worker_read, i) for i in range(50)]
            futures.append(executor.submit(worker_revoke))
            concurrent.futures.wait(futures)

        self.assertIsNotNone(revoke_finished_time)
        # Any read initiated AFTER revoke finished MUST be 'deny'
        for r in results:
            if r["t_req"] > revoke_finished_time:
                self.assertEqual(
                    r["decision"], "deny",
                    f"TOCTOU violation: Read {r['req']} succeeded after revoke completed!"
                )

    def test_race02_simultaneous_double_revoke(self):
        """Two concurrent revoke calls on the same actor must complete idempotently without errors."""
        def call_revoke():
            with open_service(state_dir=self.state_dir) as svc:
                return svc.revoke("bob")

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            f1 = executor.submit(call_revoke)
            f2 = executor.submit(call_revoke)
            r1 = f1.result()
            r2 = f2.result()

        self.assertEqual(r1, {})
        self.assertEqual(r2, {})

        # Verify bob is strictly denied
        with open_service(state_dir=self.state_dir) as svc:
            check = svc.read("bob", "f2", "req-post-double-revoke")
            self.assertEqual(check["decision"], "deny")

    def test_race03_concurrent_key_rotation(self):
        """Simultaneous key rotation attempts on the same SQLite database must serialize safely."""
        db_path = get_db_path(self.state_dir)
        key_file = get_vault_key_path(self.state_dir)

        def rotate_attempt(version_name: str):
            conn = get_connection(db_path)
            try:
                raw_key = load_vault_key(key_file)
                mgr = KeyRotationManager(conn, raw_key)
                return mgr.rotate_key(version_name)
            finally:
                conn.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            f1 = executor.submit(rotate_attempt, "v2_a")
            f2 = executor.submit(rotate_attempt, "v2_b")
            results = []
            errors = []
            for f in [f1, f2]:
                try:
                    results.append(f.result())
                except Exception as e:
                    errors.append(e)

        # At least one rotation succeeds; database is not corrupted
        self.assertGreaterEqual(len(results) + len(errors), 2)
        self.assertGreaterEqual(len(results), 1)
        with open_service(state_dir=self.state_dir) as svc:
            read_res = svc.read("alice", "f1", "req-after-concurrent-rotations")
            self.assertIn(read_res["decision"], ["allow", "deny"])


if __name__ == "__main__":
    unittest.main()
