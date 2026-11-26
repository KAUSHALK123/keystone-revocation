"""Tests for official adapter subprocess robustness and Contract v1 compliance (AD01 - AD10)."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class TestAdapterCLI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.env = os.environ.copy()
        self.env["TRACK4_STATE_DIR"] = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()

    def run_adapter(self, request_obj: dict | str, env=None) -> tuple[int, str, str]:
        """Execute track4_service.py in a fresh subprocess feeding JSON to stdin."""
        target_env = env or self.env
        cmd = [sys.executable, "-B", str(ROOT / "track4_service.py")]
        
        input_data = json.dumps(request_obj) if isinstance(request_obj, dict) else str(request_obj)
        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            env=target_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = proc.communicate(input_data, timeout=8.0)
        return proc.returncode, stdout, stderr

    def test_ad01_valid_setup_produces_single_json_line(self):
        """AD01: Valid setup produces single JSON object followed by newline."""
        req = {
            "op": "setup",
            "owners": {"f1": "user1"},
            "contents": {"f1": "Confidential"},
            "disabled": [],
            "key_material": "marker-token-12345"
        }
        rc, stdout, stderr = self.run_adapter(req)
        self.assertEqual(rc, 0)
        self.assertTrue(stdout.endswith("\n"))
        lines = stdout.strip().split("\n")
        self.assertEqual(len(lines), 1)
        data = json.loads(lines[0])
        self.assertEqual(data, {"ready": True})

    def test_ad02_malformed_json_fails_safely(self):
        """AD02: Malformed JSON on stdin exits code 1 with clean stderr error."""
        rc, stdout, stderr = self.run_adapter("{invalid-json-without-quotes")
        self.assertEqual(rc, 1)
        self.assertEqual(stdout, "")
        self.assertIn("Request failed", stderr)

    def test_ad03_unsupported_operation_handled(self):
        """AD03: Unknown operation returns unsupported_operation JSON object."""
        rc, stdout, stderr = self.run_adapter({"op": "non_existent_op"})
        self.assertEqual(rc, 0)
        data = json.loads(stdout.strip())
        self.assertEqual(data, {"error": "unsupported_operation"})

    def test_ad04_empty_stdin_fails_safely(self):
        """AD04: Empty standard input exits code 1."""
        rc, stdout, stderr = self.run_adapter("")
        self.assertEqual(rc, 1)

    def test_ad07_no_secrets_leaked_in_output(self):
        """AD07: Secret key_material marker never appears in stdout or stderr."""
        marker = "ULTRA_SENSITIVE_SECRET_MARKER_998877"
        req = {
            "op": "setup",
            "owners": {"f1": "user1"},
            "contents": {"f1": "secret"},
            "disabled": [],
            "key_material": marker
        }
        rc, stdout, stderr = self.run_adapter(req)
        self.assertNotIn(marker, stdout)
        self.assertNotIn(marker, stderr)


if __name__ == "__main__":
    unittest.main()
