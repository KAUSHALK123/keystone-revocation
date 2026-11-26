"""Tests for distributed multi-node revocation propagation, PEP caching, and latency tracking (REV01 - REV10)."""
from pathlib import Path
import tempfile
import unittest

from quantumvault.core.service import QuantumVaultService
from quantumvault.distributed.cluster import ClusterCoordinator
from quantumvault.iam.authentication import generate_device_keypair
from quantumvault.iam.device import DeviceManager
from quantumvault.iam.recovery import RecoveryManager


class TestDistributedRevocation(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp_dir.name)

        # Initialize base state with setup
        self.service = QuantumVaultService(state_dir=self.state_dir)
        self.service.setup(
            owners={"asset-owner-1": "owner-1", "asset-peer-1": "peer-1"},
            contents={"asset-owner-1": "Confidential Project Alpha", "asset-peer-1": "Peer Data"},
            disabled=[],
            key_material="cluster-revocation-test-secret"
        )
        self.service.close()

        # Initialize 3-node cluster coordinator
        self.cluster = ClusterCoordinator(state_dir=self.state_dir, node_count=3)

    def tearDown(self):
        self.cluster.close()
        self.temp_dir.cleanup()

    def test_rev01_cluster_coordinator_initializes_three_nodes(self):
        """REV01: Cluster coordinator initializes with 3 nodes (Node A, Node B, Node C)."""
        nodes = self.cluster.nodes
        self.assertEqual(len(nodes), 3)
        self.assertIn("node-a", nodes)
        self.assertIn("node-b", nodes)
        self.assertIn("node-c", nodes)

    def test_rev02_authoritative_revocation_advances_epoch(self):
        """REV02: Authoritative revocation advances the monotonic cluster epoch."""
        initial_epoch = self.cluster.authority.get_current_epoch()
        result = self.cluster.broadcast_revocation("owner-1", entity_type="actor")
        self.assertGreater(result["epoch"], initial_epoch)
        self.assertEqual(result["epoch"], self.cluster.authority.get_current_epoch())

    def test_rev03_revocation_hash_is_deterministic(self):
        """REV03: Revocation hash commits deterministically to active revocations."""
        hash1 = self.cluster.authority.compute_revocation_hash()
        self.cluster.authority.issue_revocation("actor-x", "actor")
        hash2 = self.cluster.authority.compute_revocation_hash()
        self.assertNotEqual(hash1, hash2)

    def test_rev04_broadcast_updates_all_node_pep_caches(self):
        """REV04: Revocation broadcast updates Node A, B, and C local PEP caches."""
        self.cluster.broadcast_revocation("owner-1", entity_type="actor")
        for name, node in self.cluster.nodes.items():
            self.assertIn(("owner-1", "actor"), node.cached_revocations, f"{name} cache missing revocation")

    def test_rev05_propagation_latency_is_measured(self):
        """REV05: Revocation propagation latency is measured per node and in total."""
        res = self.cluster.broadcast_revocation("owner-1", entity_type="actor")
        self.assertIn("node_latencies_ms", res)
        self.assertIn("total_propagation_ms", res)
        self.assertIn("node-a", res["node_latencies_ms"])
        self.assertIn("node-b", res["node_latencies_ms"])
        self.assertIn("node-c", res["node_latencies_ms"])
        self.assertGreaterEqual(res["total_propagation_ms"], 0.0)

    def test_rev06_immediate_enforcement_on_all_nodes(self):
        """REV06: Revocation causes immediate read denial across all 3 nodes."""
        # 1. Before revocation: read succeeds on all nodes
        for name, node in self.cluster.nodes.items():
            read_res = node.read("owner-1", "asset-owner-1", f"req-pre-{name}")
            self.assertEqual(read_res["decision"], "allow", f"{name} should allow read before revocation")

        # 2. Broadcast revocation
        self.cluster.broadcast_revocation("owner-1", entity_type="actor")

        # 3. After revocation: read is denied on all nodes
        for name, node in self.cluster.nodes.items():
            read_res = node.read("owner-1", "asset-owner-1", f"req-post-{name}")
            self.assertEqual(read_res["decision"], "deny", f"{name} should deny read after revocation")

    def test_rev07_device_level_revocation_broadcast(self):
        """REV07: Device-level revocation broadcast is enforced across all nodes."""
        dev_mgr = DeviceManager(self.cluster.authority.conn)
        _, pub = generate_device_keypair()
        dev_mgr.enroll_device("owner-1", "dev-phone-lost", pub)

        # Broadcast device revocation
        self.cluster.broadcast_revocation("dev-phone-lost", entity_type="device")

        for name, node in self.cluster.nodes.items():
            read_res = node.read("owner-1", "asset-owner-1", f"req-dev-{name}", device_id="dev-phone-lost")
            self.assertEqual(read_res["decision"], "deny", f"{name} failed to deny revoked device")

    def test_rev08_unaffected_peer_retains_access(self):
        """REV08: Revoking owner-1 leaves unaffected peer-1 able to read on all nodes."""
        self.cluster.broadcast_revocation("owner-1", entity_type="actor")
        for name, node in self.cluster.nodes.items():
            read_res = node.read("peer-1", "asset-peer-1", f"req-peer-{name}")
            self.assertEqual(read_res["decision"], "allow", f"{name} erroneously denied unaffected peer")

    def test_rev09_idempotent_revocation_broadcast(self):
        """REV09: Repeating the same revocation broadcast is safe and maintains consistency."""
        res1 = self.cluster.broadcast_revocation("owner-1", entity_type="actor")
        res2 = self.cluster.broadcast_revocation("owner-1", entity_type="actor")
        self.assertGreater(res2["epoch"], res1["epoch"])
        for node in self.cluster.nodes.values():
            self.assertIn(("owner-1", "actor"), node.cached_revocations)

    def test_rev10_recovery_and_reenrollment_restores_access(self):
        """REV10: Account recovery with new device restores access across nodes."""
        conn = self.cluster.authority.conn
        dev_mgr = DeviceManager(conn)
        rec_mgr = RecoveryManager(conn)

        _, pub_old = generate_device_keypair()
        dev_mgr.enroll_device("owner-1", "dev-old", pub_old)
        codes = rec_mgr.generate_recovery_codes("owner-1", count=1)

        # Revoke old device across cluster
        self.cluster.broadcast_revocation("dev-old", entity_type="device")

        # Recover using recovery code and enroll replacement device
        _, pub_new = generate_device_keypair()
        rec_res = rec_mgr.recover_and_replace_device(
            actor_id="owner-1",
            recovery_code=codes[0],
            new_device_id="dev-new",
            new_public_key_b64=pub_new
        )
        self.assertTrue(rec_res["replacement_confirmed"])

        # Sync cluster with updated state
        self.cluster.sync_all()

        # Read with dev-new succeeds across nodes
        for name, node in self.cluster.nodes.items():
            read_res = node.read("owner-1", "asset-owner-1", f"req-rec-{name}", device_id="dev-new")
            self.assertEqual(read_res["decision"], "allow")


if __name__ == "__main__":
    unittest.main()
