"""Integration and unit tests for QuantumVault Web API and SOC Dashboard."""
import unittest

try:
    from fastapi.testclient import TestClient
    from quantumvault.web.app import app
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False


@unittest.skipUnless(FASTAPI_AVAILABLE, "Optional web dependencies (requirements-web.txt) not installed")
class TestQuantumVaultWebAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_status_endpoint(self):
        res = self.client.get("/api/v1/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["app"], "QUANTUMVAULT")
        self.assertEqual(data["operator"], "sec-admin")
        self.assertEqual(data["backend_status"], "operational")
        self.assertIn("ML-KEM-768 (FIPS 203)", data["pqc_algorithms"])

    def test_02_cluster_status(self):
        res = self.client.get("/api/v1/cluster/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertGreaterEqual(len(data["nodes"]), 4)
        node_names = [n["name"] for n in data["nodes"]]
        self.assertTrue(any("Authority" in name for name in node_names))
        self.assertTrue(any("Node A" in name for name in node_names))

    def test_03_revocation_broadcast(self):
        res = self.client.post("/api/v1/cluster/revoke", json={
            "entity_id": "test-user-rev",
            "entity_type": "actor",
            "reason": "web_test_revocation"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("epoch", data)
        self.assertIn("revocation_hash", data)
        self.assertGreaterEqual(len(data["confirmed_nodes"]), 3)
        self.assertGreater(data["total_propagation_ms"], 0.0)

    def test_04_node_partition_and_reconnect(self):
        # Disconnect node-c
        res_disc = self.client.post("/api/v1/cluster/partition-node", json={
            "node_id": "node-c",
            "action": "disconnect"
        })
        self.assertEqual(res_disc.status_code, 200)
        self.assertEqual(res_disc.json()["status"], "offline")
        self.assertEqual(res_disc.json()["enforcement"], "fail-closed")

        # Reconnect node-c
        res_rec = self.client.post("/api/v1/cluster/partition-node", json={
            "node_id": "node-c",
            "action": "reconnect"
        })
        self.assertEqual(res_rec.status_code, 200)
        self.assertEqual(res_rec.json()["status"], "online")

    def test_05_key_rotation(self):
        res = self.client.post("/api/v1/crypto/rotate-key")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "rotated")
        self.assertTrue(data["transfers_continue"])
        self.assertTrue(data["retired_keys_rejected"])

    def test_06_lost_device_11_step_demo(self):
        res = self.client.post("/api/v1/demo/lost-device")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "COMPLETED")
        self.assertEqual(len(data["steps"]), 11)
        self.assertGreater(data["revocation_latency_ms"], 0.0)

    def test_07_detection_overview_and_events(self):
        overview = self.client.get("/api/v1/detection/overview")
        self.assertEqual(overview.status_code, 200)
        self.assertEqual(overview.json()["events_processed"], 22)

        events_res = self.client.get("/api/v1/detection/practice-events")
        self.assertEqual(events_res.status_code, 200)
        events = events_res.json()
        self.assertEqual(len(events), 22)
        evt_ids = [e["event_id"] for e in events]
        self.assertIn("evt-001", evt_ids)
        self.assertIn("evt-015", evt_ids)

    def test_08_detection_service_graph_and_metrics(self):
        graph = self.client.get("/api/v1/detection/service-graph")
        self.assertEqual(graph.status_code, 200)
        g_data = graph.json()
        self.assertGreaterEqual(len(g_data["nodes"]), 6)
        self.assertTrue(any(e["status"] == "suspicious_attempted" for e in g_data["edges"]))

        metrics = self.client.get("/api/v1/detection/metrics")
        self.assertEqual(metrics.status_code, 200)
        m_data = metrics.json()
        self.assertEqual(m_data["f1_score"], 1.0)
        self.assertEqual(m_data["exact_accuracy"], 1.0)
        self.assertEqual(m_data["false_alerts_per_1000_benign"], 0.0)

    def test_09_pqc_handshake_and_messaging(self):
        hs = self.client.post("/api/v1/messaging/demo-handshake", json={
            "initiator": "alice",
            "responder": "bob"
        })
        self.assertEqual(hs.status_code, 200)
        hs_data = hs.json()
        self.assertTrue(hs_data["session_key_derived"])
        self.assertTrue(hs_data["ephemeral_keys_zeroized"])
        self.assertEqual(len(hs_data["stages"]), 3)

        msg = self.client.post("/api/v1/messaging/send", json={
            "sender": "alice",
            "recipient": "bob",
            "plaintext": "Secret Integration Verification Message"
        })
        self.assertEqual(msg.status_code, 200)
        self.assertEqual(msg.json()["plaintext_revealed_to_recipient"], "Secret Integration Verification Message")

    def test_10_replay_and_tampering_rejection(self):
        replay = self.client.post("/api/v1/messaging/test-replay")
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json()["status"], "REPLAY_REJECTED")

        tamper = self.client.post("/api/v1/messaging/test-tamper-recipient")
        self.assertEqual(tamper.status_code, 200)
        self.assertEqual(tamper.json()["status"], "TAMPER_DETECTED")
        self.assertFalse(tamper.json()["ciphertext_decrypted"])

    def test_11_forward_secrecy_simulation(self):
        pfs = self.client.post("/api/v1/messaging/test-forward-secrecy")
        self.assertEqual(pfs.status_code, 200)
        pfs_data = pfs.json()
        self.assertTrue(pfs_data["forward_secrecy_preserved"])
        self.assertFalse(pfs_data["captured_transcript_decrypted"])

    def test_12_transport_and_offline_outbox(self):
        trans = self.client.post("/api/v1/messaging/test-transport-fault?fault_type=reorder")
        self.assertEqual(trans.status_code, 200)
        self.assertTrue(trans.json()["reassembly_success"])

        outbox = self.client.post("/api/v1/messaging/test-offline-outbox")
        self.assertEqual(outbox.status_code, 200)
        self.assertTrue(outbox.json()["delivery_when_active"])
        self.assertFalse(outbox.json()["delivery_when_revoked"])

    def test_13_security_lab_scenarios(self):
        scenarios = self.client.get("/api/v1/lab/scenarios")
        self.assertEqual(scenarios.status_code, 200)
        self.assertEqual(len(scenarios.json()), 40)

        single = self.client.post("/api/v1/lab/run?name=atomic_key_rotation")
        self.assertEqual(single.status_code, 200)
        self.assertTrue(single.json()["passed"])

    def test_14_combined_scenario_endpoint(self):
        res = self.client.post("/api/v1/lab/run-combined")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["steps_passed"], 40)
        self.assertEqual(data["total_steps"], 40)

    def test_15_evidence_viewer_and_path_traversal_guard(self):
        files = self.client.get("/api/v1/lab/evidence/list")
        self.assertEqual(files.status_code, 200)
        self.assertIn("files", files.json())

        # Path traversal attempt must be blocked with 403
        attack = self.client.get("/api/v1/lab/evidence/view?file_path=../../../../windows/system.ini")
        self.assertEqual(attack.status_code, 403)


if __name__ == "__main__":
    unittest.main()
