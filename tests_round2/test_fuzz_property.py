"""Group 2: Property and Fuzzing Tests for QuantumVault Adapter and Dispatcher."""
from __future__ import annotations

import json
import os
from pathlib import Path
import random
import string
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class TestPropertyFuzz(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.env = os.environ.copy()
        self.env["TRACK4_STATE_DIR"] = self.temp_dir.name

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def run_adapter(self, raw_input_bytes: bytes) -> tuple[int, str, str]:
        cmd = [sys.executable, "-B", str(ROOT / "track4_service.py")]
        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            env=self.env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate(raw_input_bytes, timeout=10.0)
        return proc.returncode, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")

    def test_fuzz01_random_raw_bytes(self):
        """Random binary garbage on stdin should fail safely with exit code 1 and no stack trace."""
        rng = random.Random(1337)
        for i in range(50):
            size = rng.randint(1, 4096)
            garbage = rng.randbytes(size)
            rc, stdout, stderr = self.run_adapter(garbage)
            self.assertEqual(rc, 1, f"Expected non-zero exit code on garbage input run {i}")
            self.assertEqual(stdout, "")
            self.assertNotIn("Traceback", stderr)
            self.assertIn("Request failed", stderr)

    def test_fuzz02_deeply_nested_json(self):
        """Deeply nested JSON structures must not cause Python RecursionError or crash."""
        nested = {}
        curr = nested
        for _ in range(300):
            curr["child"] = {}
            curr = curr["child"]
        curr["op"] = "read"
        raw = json.dumps(nested).encode("utf-8")
        rc, stdout, stderr = self.run_adapter(raw)
        # Should cleanly exit 0 with deny or exit 1 with sanitized error, NEVER crash with RecursionError
        self.assertNotIn("RecursionError", stderr)
        self.assertNotIn("Traceback", stderr)

    def test_fuzz03_oversized_payloads(self):
        """Oversized fields (e.g. 2MB string in key_material or actor) handled gracefully."""
        huge_str = "A" * (2 * 1024 * 1024)
        req = {
            "op": "setup",
            "owners": {"f1": "alice"},
            "contents": {"f1": "secret"},
            "disabled": [],
            "key_material": huge_str
        }
        raw = json.dumps(req).encode("utf-8")
        rc, stdout, stderr = self.run_adapter(raw)
        self.assertNotIn("Traceback", stderr)
        self.assertNotIn("MemoryError", stderr)

    def test_fuzz04_nul_bytes_in_fields(self):
        """NUL bytes inside actor, asset, or challenge fields must be rejected or handled without crashing."""
        nul_reqs = [
            {"op": "read", "actor": "alice\x00admin", "asset": "f1", "request_id": "r01"},
            {"op": "read", "actor": "alice", "asset": "f1\x00secret", "request_id": "r02"},
            {"op": "protected_read", "actor": "alice", "asset": "f1", "challenge": "c\x00h", "public_key": "AAA"}
        ]
        for req in nul_reqs:
            raw = json.dumps(req).encode("utf-8")
            rc, stdout, stderr = self.run_adapter(raw)
            self.assertNotIn("Traceback", stderr)
            if rc == 0:
                data = json.loads(stdout.strip())
                self.assertEqual(data.get("decision"), "deny")

    def test_fuzz05_unicode_normalization_and_tricks(self):
        """Unicode lookalikes, RTL marks, and weird normalizations must not crash or leak."""
        tricky_strings = [
            "\u202e\u202dadmin\u202c",  # Bidirectional override
            "\ufeff",                   # Zero width no-break space
            "\uff41\uff4c\uff49\uff43\uff45",  # Fullwidth 'alice'
            "аlice",                    # Cyrillic 'а' lookalike
            "\ud800",                   # Lone surrogate (invalid in strict utf-8)
            "\x00\x01\x02\x1f",         # Control characters
        ]
        for s in tricky_strings:
            req = {"op": "read", "actor": s, "asset": "f1", "request_id": "r01"}
            raw = json.dumps(req, ensure_ascii=False).encode("utf-8", errors="replace")
            rc, stdout, stderr = self.run_adapter(raw)
            self.assertNotIn("Traceback", stderr)

    def test_fuzz06_wrong_types_on_all_fields(self):
        """Pass arrays, numbers, dicts, booleans, and nulls into every field."""
        bad_types = [
            {"op": 12345},
            {"op": ["setup"]},
            {"op": {"sub": "setup"}},
            {"op": "read", "actor": 123, "asset": True, "request_id": None},
            {"op": "read", "actor": ["alice"], "asset": {"path": "f1"}, "request_id": 999},
            {"op": "setup", "owners": "not-a-dict", "contents": [], "disabled": "alice", "key_material": 123},
            {"op": "revoke", "actor": {"id": "alice"}},
            {"op": "audit", "request_id": [1, 2, 3]},
            {"op": "protected_read", "actor": False, "asset": 0, "challenge": {}, "public_key": []}
        ]
        for req in bad_types:
            raw = json.dumps(req).encode("utf-8")
            rc, stdout, stderr = self.run_adapter(raw)
            self.assertNotIn("Traceback", stderr)
            # Response must be clean JSON or clean exit 1
            if rc == 0:
                self.assertTrue(stdout.strip().startswith("{"))


if __name__ == "__main__":
    unittest.main()
