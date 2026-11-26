"""Tests for offline node handling, partition isolation, and fail-closed security (OFF01 - OFF08)."""
from pathlib import Path
import tempfile
import unittest

from quantumvault.core.service import QuantumVaultService
from quantumvault.crypto.pqc_kem import MLKEM768
from quantumvault.distributed.cluster import ClusterCoordinator


class TestOfflineNodes(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp_dir.name)

        self.service = QuantumVaultService(state_dir=self.state_dir)
        self.service.setup(
            owners={"doc-1": "user-1"},
            contents={"doc-1": "Top Secret Document"},
            disabled=[],
            key_material="offline-node-test-secret"
        )
        self.service.close()

        self.cluster = ClusterCoordinator(state_dir=self.state_dir, node_count=3)
        self.pqc = MLKEM768()

    def tearDown(self):
        self.cluster.close()
        self.temp_dir.cleanup()

    def test_off01_healthy_node_serves_requests(self):
        """OFF01: Healthy node in normal state allows authorized read."""
        node_a = self.cluster.get_node("node-a")
        res = node_a.read("user-1", "doc-1", "req-h1")
        self.assertEqual(res["decision"], "allow")
        self.assertEqual(res["body"], "Top Secret Document")

    def test_off02_partitioned_node_fails_closed(self):
        """OFF02: Partitioned node with status 'offline' immediately fails closed."""
        self.cluster.partition_node("node-c")
        node_c = self.cluster.get_node("node-c")

        res = node_c.read("user-1", "doc-1", "req-off-1")
        self.assertEqual(res["decision"], "deny")
        self.assertNotIn("body", res)

    def test_off03_heartbeat_timeout_fails_closed(self):
        """OFF03: Node with heartbeat aged beyond threshold (>5.0s) fails closed."""
        node_b = self.cluster.get_node("node-b")
        # Artificially age heartbeat by 10 seconds
        node_b.simulate_heartbeat_timeout(seconds_ago=10.0)

        self.assertFalse(node_b.is_healthy())
        res = node_b.read("user-1", "doc-1", "req-timeout-1")
        self.assertEqual(res["decision"], "deny")
        self.assertEqual(res.get("rule"), "node_offline_fail_closed")

    def test_off04_offline_node_denies_protected_read(self):
        """OFF04: Offline node denies post-quantum protected read without encapsulation."""
        self.cluster.partition_node("node-b")
        node_b = self.cluster.get_node("node-b")

        pk_bytes, _ = self.pqc.generate_keypair()
        pk_b64 = self.pqc.encode_public_key(pk_bytes)

        res = node_b.protected_read("user-1", "doc-1", challenge="chal-1", public_key=pk_b64)
        self.assertEqual(res["decision"], "deny")
        self.assertNotIn("ciphertext", res)
        self.assertNotIn("proof", res)

    def test_off05_reconnected_node_synchronizes_missed_revocations(self):
        """OFF05: Partitioned node that missed a revocation syncs upon reconnection."""
        # 1. Partition node-c
        self.cluster.partition_node("node-c")
        node_c = self.cluster.get_node("node-c")
        self.assertFalse(node_c.is_healthy())

        # 2. Revocation broadcast happens while node-c is offline
        self.cluster.broadcast_revocation("user-1", entity_type="actor")
        self.assertNotIn(("user-1", "actor"), node_c.cached_revocations)

        # 3. Reconnect node-c and synchronize
        self.cluster.reconnect_node("node-c")
        self.assertTrue(node_c.is_healthy())
        self.assertIn(("user-1", "actor"), node_c.cached_revocations)

    def test_off06_reconnected_node_enforces_synced_revocation(self):
        """OFF06: Reconnected node correctly enforces the synchronized revocation."""
        self.cluster.partition_node("node-a")
        self.cluster.broadcast_revocation("user-1", entity_type="actor")
        self.cluster.reconnect_node("node-a")

        node_a = self.cluster.get_node("node-a")
        res = node_a.read("user-1", "doc-1", "req-reconnect-read")
        self.assertEqual(res["decision"], "deny")

    def test_off07_partial_network_partition_isolation(self):
        """OFF07: In partial partition, online nodes serve requests while offline node fails closed."""
        self.cluster.partition_node("node-c")

        # Online nodes A and B serve requests
        res_a = self.cluster.get_node("node-a").read("user-1", "doc-1", "req-part-a")
        res_b = self.cluster.get_node("node-b").read("user-1", "doc-1", "req-part-b")
        self.assertEqual(res_a["decision"], "allow")
        self.assertEqual(res_b["decision"], "allow")

        # Partitioned node C fails closed
        res_c = self.cluster.get_node("node-c").read("user-1", "doc-1", "req-part-c")
        self.assertEqual(res_c["decision"], "deny")

    def test_off08_simultaneous_multi_node_partition(self):
        """OFF08: Multiple simultaneous partitions preserve security invariants."""
        self.cluster.partition_node("node-a")
        self.cluster.partition_node("node-b")

        self.assertEqual(self.cluster.get_node("node-a").read("user-1", "doc-1", "req-m1")["decision"], "deny")
        self.assertEqual(self.cluster.get_node("node-b").read("user-1", "doc-1", "req-m2")["decision"], "deny")
        # Node C remains online and serves request
        self.assertEqual(self.cluster.get_node("node-c").read("user-1", "doc-1", "req-m3")["decision"], "allow")


if __name__ == "__main__":
    unittest.main()
