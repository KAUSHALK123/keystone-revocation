"""Integration, security, and regression tests for QuantumVault Web API and SOC Dashboard."""
import unittest
from fastapi.testclient import TestClient

from quantumvault.web.app import app
from quantumvault.web.authentication import get_operator_token


class TestQuantumVaultWebAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.auth_headers = {"X-Operator-Token": get_operator_token()}

    def test_00_authentication_and_security_headers(self):
        # Missing token must fail with 401
        r_missing = self.client.get("/api/v1/status")
        self.assertEqual(r_missing.status_code, 401)

        # Invalid token must fail with 401
        r_bad = self.client.get("/api/v1/status", headers={"X-Operator-Token": "wrong-token"})
        self.assertEqual(r_bad.status_code, 401)

        # Dashboard HTML injects meta token, sets HttpOnly cookie, and emits security headers
        r_home = self.client.get("/")
        self.assertEqual(r_home.status_code, 200)
        self.assertIn("qv-operator-token", r_home.text)
        self.assertEqual(r_home.headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(r_home.headers.get("x-frame-options"), "DENY")

    def test_01_status_and_integrity_endpoints(self):
        res = self.client.get("/api/v1/status", headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["app"], "QUANTUMVAULT")
        self.assertEqual(data["operator"], "sec-admin")
        self.assertEqual(data["backend_status"], "operational")
        self.assertTrue(data["audit_verified"])
        self.assertIn("ML-KEM-768 (FIPS 203)", data["pqc_algorithms"])

        integ = self.client.get("/api/v1/integrity/status", headers=self.auth_headers)
        self.assertEqual(integ.status_code, 200)
        i_data = integ.json()
        self.assertTrue(i_data["audit_chain_verified"])
        self.assertFalse(i_data["tamper_detected"])
        self.assertTrue(i_data["external_checkpoint_valid"])
        self.assertTrue(i_data["backup_verified"])
        self.assertTrue(i_data["last_backup_digest"].startswith("sha256:"))

    def test_02_cluster_status_and_iam_devices(self):
        res = self.client.get("/api/v1/cluster/status", headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["cluster_mode"], "simulated_in_process")
        self.assertGreaterEqual(len(data["nodes"]), 4)
        node_names = [n["name"] for n in data["nodes"]]
        self.assertTrue(any("Authority" in name for name in node_names))
        self.assertTrue(any("Node A" in name for name in node_names))

        devs = self.client.get("/api/v1/iam/devices", headers=self.auth_headers)
        self.assertEqual(devs.status_code, 200)
        dev_list = devs.json()
        self.assertGreaterEqual(len(dev_list), 3)
        self.assertTrue(any("ML-DSA-65" in d["algorithm"] for d in dev_list))

    def test_03_revocation_broadcast(self):
        res = self.client.post(
            "/api/v1/cluster/revoke",
            headers=self.auth_headers,
            json={"entity_id": "test-user-rev", "entity_type": "actor", "reason": "web_test_revocation"},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("epoch", data)
        self.assertIn("revocation_hash", data)
        self.assertGreaterEqual(len(data["confirmed_nodes"]), 3)
        self.assertGreater(data["total_propagation_ms"], 0.0)

    def test_04_node_partition_and_reconnect(self):
        res_disc = self.client.post(
            "/api/v1/cluster/partition-node",
            headers=self.auth_headers,
            json={"node_id": "node-c", "action": "disconnect"},
        )
        self.assertEqual(res_disc.status_code, 200)
        self.assertEqual(res_disc.json()["status"], "offline")
        self.assertEqual(res_disc.json()["enforcement"], "fail-closed")

        res_rec = self.client.post(
            "/api/v1/cluster/partition-node",
            headers=self.auth_headers,
            json={"node_id": "node-c", "action": "reconnect"},
        )
        self.assertEqual(res_rec.status_code, 200)
        self.assertEqual(res_rec.json()["status"], "online")

    def test_05_key_rotation_repeated(self):
        res1 = self.client.post("/api/v1/crypto/rotate-key", headers=self.auth_headers)
        self.assertEqual(res1.status_code, 200)
        d1 = res1.json()
        self.assertEqual(d1["status"], "rotated")
        self.assertEqual(d1["active_key_version"], "v2")

        res2 = self.client.post("/api/v1/crypto/rotate-key", headers=self.auth_headers)
        self.assertEqual(res2.status_code, 200)
        self.assertEqual(res2.json()["active_key_version"], "v3")

    def test_06_lost_device_11_step_demo(self):
        res = self.client.post("/api/v1/demo/lost-device", headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "COMPLETED")
        self.assertEqual(len(data["steps"]), 11)
        self.assertGreater(data["revocation_latency_ms"], 0.0)

    def test_07_detection_overview_and_events(self):
        overview = self.client.get("/api/v1/detection/overview", headers=self.auth_headers)
        self.assertEqual(overview.status_code, 200)
        self.assertEqual(overview.json()["events_processed"], 22)

        events_res = self.client.get("/api/v1/detection/practice-events?evaluation_mode=false", headers=self.auth_headers)
        self.assertEqual(events_res.status_code, 200)
        events = events_res.json()
        self.assertEqual(len(events), 22)
        self.assertIsNone(events[0]["ground_truth_label"])

    def test_08_detection_service_graph_and_metrics(self):
        graph = self.client.get("/api/v1/detection/service-graph", headers=self.auth_headers)
        self.assertEqual(graph.status_code, 200)
        g_data = graph.json()
        self.assertGreaterEqual(len(g_data["nodes"]), 6)
        self.assertTrue(any(e["status"] == "suspicious_attempted" for e in g_data["edges"]))

        metrics = self.client.get("/api/v1/detection/metrics", headers=self.auth_headers)
        self.assertEqual(metrics.status_code, 200)
        m_data = metrics.json()
        self.assertEqual(m_data["f1_score"], 1.0)
        self.assertEqual(m_data["exact_accuracy"], 1.0)
        self.assertEqual(m_data["false_alerts_per_1000_benign"], 0.0)

    def test_09_pqc_handshake_and_messaging(self):
        hs = self.client.post(
            "/api/v1/messaging/demo-handshake",
            headers=self.auth_headers,
            json={"initiator": "alice", "responder": "bob"},
        )
        self.assertEqual(hs.status_code, 200)
        hs_data = hs.json()
        self.assertTrue(hs_data["session_key_derived"])
        self.assertTrue(hs_data["ephemeral_keys_zeroized"])

        msg = self.client.post(
            "/api/v1/messaging/send",
            headers=self.auth_headers,
            json={"sender": "alice", "recipient": "bob", "plaintext": "Secret Integration Message"},
        )
        self.assertEqual(msg.status_code, 200)
        self.assertEqual(msg.json()["plaintext_revealed_to_recipient"], "Secret Integration Message")

    def test_10_replay_tampering_and_revoked_device_messaging(self):
        replay = self.client.post("/api/v1/messaging/test-replay", headers=self.auth_headers)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json()["status"], "REPLAY_REJECTED")

        tamper_rec = self.client.post("/api/v1/messaging/test-tamper-recipient", headers=self.auth_headers)
        self.assertEqual(tamper_rec.status_code, 200)
        self.assertFalse(tamper_rec.json()["ciphertext_decrypted"])

        tamper_ct = self.client.post("/api/v1/messaging/test-tamper-ciphertext", headers=self.auth_headers)
        self.assertEqual(tamper_ct.status_code, 200)
        self.assertEqual(tamper_ct.json()["status"], "CIPHERTEXT_TAMPER_REJECTED")
        self.assertFalse(tamper_ct.json()["ciphertext_decrypted"])

        rev_dev = self.client.post("/api/v1/messaging/test-revoked-device", headers=self.auth_headers)
        self.assertEqual(rev_dev.status_code, 200)
        self.assertTrue(rev_dev.json()["dispatch_blocked"])

    def test_11_forward_secrecy_and_transport_outbox(self):
        pfs = self.client.post("/api/v1/messaging/test-forward-secrecy", headers=self.auth_headers)
        self.assertEqual(pfs.status_code, 200)
        self.assertTrue(pfs.json()["forward_secrecy_preserved"])

        trans = self.client.post("/api/v1/messaging/test-transport-fault?fault_type=reorder", headers=self.auth_headers)
        self.assertEqual(trans.status_code, 200)
        self.assertTrue(trans.json()["reassembly_success"])

        outbox = self.client.post("/api/v1/messaging/test-offline-outbox", headers=self.auth_headers)
        self.assertEqual(outbox.status_code, 200)
        self.assertTrue(outbox.json()["delivery_when_active"])
        self.assertFalse(outbox.json()["delivery_when_revoked"])

    def test_12_security_lab_and_combined(self):
        scenarios = self.client.get("/api/v1/lab/scenarios", headers=self.auth_headers)
        self.assertEqual(scenarios.status_code, 200)
        self.assertEqual(len(scenarios.json()), 40)

        single = self.client.post("/api/v1/lab/run?name=atomic_key_rotation", headers=self.auth_headers)
        self.assertEqual(single.status_code, 200)
        self.assertTrue(single.json()["passed"])

        comb = self.client.post("/api/v1/lab/run-combined", headers=self.auth_headers)
        self.assertEqual(comb.status_code, 200)
        self.assertTrue(comb.json()["success"])
        self.assertEqual(comb.json()["steps_passed"], 40)

    def test_13_evidence_viewer_and_traversal_guards(self):
        files = self.client.get("/api/v1/lab/evidence/list", headers=self.auth_headers)
        self.assertEqual(files.status_code, 200)
        self.assertIn("files", files.json())

        for bad_path in ("../../../../windows/system.ini", "../README.md", "../evidence_sibling/x.txt"):
            attack = self.client.get(
                f"/api/v1/lab/evidence/view?file_path={bad_path}",
                headers=self.auth_headers,
            )
            self.assertEqual(attack.status_code, 403)

    def test_14_judge_demo_15_step_workflow(self):
        st = self.client.post("/api/v1/judge-demo/start", headers=self.auth_headers)
        self.assertEqual(st.status_code, 200)
        self.assertTrue(st.json()["active"])

        for expected_step in range(1, 16):
            res = self.client.post("/api/v1/judge-demo/next", headers=self.auth_headers)
            self.assertEqual(res.status_code, 200)
            body = res.json()
            self.assertEqual(body["step"], expected_step)
            self.assertEqual(body["status"], "PASS", f"Judge demo step {expected_step} failed: {body}")

        rst = self.client.post("/api/v1/judge-demo/reset", headers=self.auth_headers)
        self.assertEqual(rst.status_code, 200)
        self.assertFalse(rst.json()["active"])


if __name__ == "__main__":
    unittest.main()
