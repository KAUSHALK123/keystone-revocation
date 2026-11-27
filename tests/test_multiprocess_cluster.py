"""Tests for MultiProcessCluster (isolated processes for Node A, Node B, Node C)."""
from pathlib import Path
import tempfile
import unittest

from quantumvault.distributed.multiprocess_cluster import MultiProcessCluster


class TestMultiProcessCluster(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cluster = MultiProcessCluster(base_dir=Path(self.temp_dir.name) / "test_cluster")
        owners = {"asset-1": "alice", "asset-2": "bob"}
        contents = {"asset-1": "Top Secret Alice", "asset-2": "Bob Data"}
        self.cluster.seed_initial_state(owners, contents)
        self.assertTrue(self.cluster.start_all())

    def tearDown(self):
        self.cluster.close()
        self.temp_dir.cleanup()

    def test_mpc01_three_distinct_processes(self):
        """MPC01: Verify Node A, Node B, and Node C run as 3 distinct OS processes."""
        nodes = self.cluster.nodes
        self.assertEqual(len(nodes), 3)
        pids = {node.process.pid for node in nodes.values() if node.process}
        self.assertEqual(len(pids), 3, "Each node must have a unique OS PID")

    def test_mpc02_normal_revocation_enforced(self):
        """MPC02: Durable revocation broadcast enforces rejection on all 3 process nodes."""
        r_pre = self.cluster.nodes["node-a"].read("alice", "asset-1", "req-mpc-pre")
        self.assertEqual(r_pre.get("decision"), "allow")

        res = self.cluster.broadcast_revocation("alice", "actor")
        self.assertEqual(len(res["confirmed_nodes"]), 3)
        self.assertGreater(res["total_confirmed_latency_ms"], 0.0)

        for name, node in self.cluster.nodes.items():
            r_post = node.read("alice", "asset-1", f"req-mpc-post-{name}")
            self.assertEqual(r_post.get("decision"), "deny")

    def test_mpc03_partition_fail_closed(self):
        """MPC03: Partitioned node fails closed immediately."""
        self.cluster.nodes["node-c"].partition()
        res = self.cluster.nodes["node-c"].read("bob", "asset-2", "req-part")
        self.assertEqual(res.get("decision"), "deny")
        self.assertEqual(res.get("rule"), "node_offline_fail_closed")

    def test_mpc04_crash_restart_preserves_revocation(self):
        """MPC04: Abruptly killing and restarting Node A preserves revocation state."""
        self.cluster.broadcast_revocation("alice", "actor")
        self.cluster.nodes["node-a"].kill()
        self.assertFalse(self.cluster.nodes["node-a"].is_alive())

        restarted = self.cluster.nodes["node-a"].restart()
        self.assertTrue(restarted)
        res = self.cluster.nodes["node-a"].read("alice", "asset-1", "req-post-crash")
        self.assertEqual(res.get("decision"), "deny")

    def test_mpc05_ipc_replay_rejected_after_worker_restart(self):
        """MPC05: IPC replay protection remains effective across process kill and restart."""
        node_a = self.cluster.nodes["node-a"]
        fixed_msg_id = "msg-ipc-replay-persistent-001"

        # 1. Send first command with fixed msg_id
        res1 = node_a.send_cmd("ping", msg_id=fixed_msg_id)
        self.assertEqual(res1.get("status"), "ok")

        # 2. Immediate replay must be rejected
        res2 = node_a.send_cmd("ping", msg_id=fixed_msg_id)
        self.assertEqual(res2.get("status"), "error")
        self.assertEqual(res2.get("error"), "replay_detected")

        # 3. Abruptly kill Node A and restart
        node_a.kill()
        self.assertFalse(node_a.is_alive())
        self.assertTrue(node_a.restart())

        # 4. Replay of pre-crash msg_id against fresh worker process MUST STILL be rejected
        res3 = node_a.send_cmd("ping", msg_id=fixed_msg_id)
        self.assertEqual(res3.get("status"), "error")
        self.assertEqual(res3.get("error"), "replay_detected")


if __name__ == "__main__":
    unittest.main()
