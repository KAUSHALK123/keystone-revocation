"""Unit tests for the Adversarial Script Injector Web API."""
import unittest
from fastapi.testclient import TestClient

from quantumvault.web.app import app
from quantumvault.web.authentication import get_operator_token


class TestScriptInjectorAPI(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.token = get_operator_token()
        self.headers = {"X-Operator-Token": self.token}

    def test_01_unauthenticated_request_rejected(self):
        res = self.client.get("/api/v1/injector/presets")
        self.assertEqual(res.status_code, 401)

    def test_02_get_presets_returns_expected_catalog(self):
        res = self.client.get("/api/v1/injector/presets", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("presets", data)
        preset_ids = [p["id"] for p in data["presets"]]
        self.assertIn("v6", preset_ids)
        self.assertIn("extreme", preset_ids)
        self.assertIn("normal", preset_ids)
        self.assertIn("easy", preset_ids)
        self.assertIn("track4", preset_ids)
        self.assertIn("custom", preset_ids)

    def test_03_execute_custom_script_success(self):
        script = """
import sys
print("PASS  [custom] sample-invariant: invariant held")
print("SUMMARY {'PASS': 1, 'FAIL': 0, 'ERROR': 0, 'SKIP': 0}")
sys.exit(0)
"""
        res = self.client.post("/api/v1/injector/execute", json={
            "script_content": script,
            "preset_name": "custom",
            "seed": 987654321,
            "rounds": 1,
            "timeout_seconds": 15
        }, headers=self.headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["exit_code"], 0)
        self.assertEqual(data["summary"]["PASS"], 1)
        self.assertEqual(data["summary"]["FAIL"], 0)
        self.assertEqual(len(data["tests_breakdown"]), 1)
        self.assertEqual(data["tests_breakdown"][0]["name"], "sample-invariant")

    def test_04_execute_failing_script_detected(self):
        script = """
import sys
print("FAIL  [custom] sample-failure: security invariant violated")
print("SUMMARY {'PASS': 0, 'FAIL': 1, 'ERROR': 0, 'SKIP': 0}")
sys.exit(1)
"""
        res = self.client.post("/api/v1/injector/execute", json={
            "script_content": script,
            "preset_name": "custom",
            "seed": 987654321,
            "rounds": 1,
            "timeout_seconds": 15
        }, headers=self.headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertFalse(data["success"])
        self.assertEqual(data["exit_code"], 1)
        self.assertEqual(data["summary"]["FAIL"], 1)


if __name__ == "__main__":
    unittest.main()
