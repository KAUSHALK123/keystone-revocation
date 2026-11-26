"""Cluster coordinator managing Node A, Node B, Node C and measuring revocation propagation."""
from pathlib import Path
import time
from typing import Any

from quantumvault.config import get_state_dir
from quantumvault.distributed.authority import SecurityAuthority
from quantumvault.distributed.node import ServiceNode


class ClusterCoordinator:
    """Orchestrates 3-node mock cluster (Node A, B, C) and measures propagation latency."""

    def __init__(self, state_dir: Path | None = None, node_count: int = 3):
        self.state_dir = state_dir or get_state_dir()
        self.authority = SecurityAuthority(state_dir=self.state_dir)
        self.nodes: dict[str, ServiceNode] = {}

        # Default 3 mock service nodes: node-a, node-b, node-c
        letters = ["a", "b", "c", "d", "e"]
        for i in range(node_count):
            name = f"node-{letters[i]}" if i < len(letters) else f"node-{i}"
            self.nodes[name] = ServiceNode(
                node_id=name,
                state_dir=self.state_dir,
                heartbeat_threshold_seconds=5.0
            )

        # Initial sync of all nodes
        self.sync_all()

    def get_node(self, node_id: str) -> ServiceNode | None:
        """Retrieve a specific node by ID."""
        return self.nodes.get(node_id)

    def sync_all(self) -> None:
        """Synchronize all nodes with current authority state."""
        epoch = self.authority.get_current_epoch()
        active_key = self.authority.get_active_key_version()
        revs = self.authority.get_all_revocations()

        for node in self.nodes.values():
            if node.status == "online":
                node.sync(epoch=epoch, active_key_version=active_key, revocations=revs)

    def sync_node(self, node_id: str) -> None:
        """Synchronize an individual reconnected node."""
        node = self.nodes.get(node_id)
        if not node:
            return
        epoch = self.authority.get_current_epoch()
        active_key = self.authority.get_active_key_version()
        revs = self.authority.get_all_revocations()
        node.sync(epoch=epoch, active_key_version=active_key, revocations=revs)

    def partition_node(self, node_id: str) -> None:
        """Simulate a network partition on a specific node."""
        node = self.nodes.get(node_id)
        if node:
            node.set_offline()

    def reconnect_node(self, node_id: str) -> None:
        """Reconnect a partitioned node and synchronize it."""
        node = self.nodes.get(node_id)
        if node:
            node.set_online()
            self.sync_node(node_id)

    def broadcast_revocation(self, entity_id: str, entity_type: str = "actor",
                             reason: str = "cluster_broadcast_revocation") -> dict[str, Any]:
        """Commit revocation at authority, propagate to nodes, and confirm real authorization enforcement."""
        # 1. Authoritative commit measurement
        t_auth_start = time.perf_counter()
        auth_record = self.authority.issue_revocation(
            entity_id=entity_id,
            entity_type=entity_type,
            reason=reason
        )
        t_auth_end = time.perf_counter()
        auth_commit_latency_ms = round((t_auth_end - t_auth_start) * 1000.0, 4)

        # 2. Measure delivery and actual enforcement across cluster nodes
        t_start = time.perf_counter()
        latencies_ms: dict[str, float] = {}
        probe_latencies_ms: dict[str, float] = {}
        confirmed_nodes: list[str] = []
        nodes_updated = 0
        nodes_offline = 0

        for name, node in self.nodes.items():
            t_node_start = time.perf_counter()
            if node.is_healthy():
                # Apply cache update
                node.apply_revocation(entity_id=entity_id, entity_type=entity_type)
                t_node_delivery = time.perf_counter()
                delivery_ms = round((t_node_delivery - t_node_start) * 1000.0, 4)
                latencies_ms[name] = delivery_ms

                # Real authorization enforcement probe
                probe_res = node.read(
                    actor=entity_id if entity_type == "actor" else "probe-user",
                    asset="probe-asset",
                    request_id=f"probe-{name}-{int(time.time()*1000)}",
                    device_id=entity_id if entity_type == "device" else None
                )
                t_node_probe = time.perf_counter()
                probe_ms = round((t_node_probe - t_node_delivery) * 1000.0, 4)
                probe_latencies_ms[name] = probe_ms

                # Confirm denial is strictly enforced
                if probe_res.get("decision") == "deny":
                    confirmed_nodes.append(name)
                    nodes_updated += 1
            else:
                latencies_ms[name] = -1.0  # Offline / unreachable
                probe_latencies_ms[name] = -1.0
                nodes_offline += 1

        t_total_end = time.perf_counter()
        total_propagation_ms = round((t_total_end - t_start) * 1000.0, 4)

        return {
            "epoch": auth_record["epoch"],
            "entity_id": entity_id,
            "entity_type": entity_type,
            "revocation_hash": auth_record["revocation_hash"],
            "auth_commit_latency_ms": auth_commit_latency_ms,
            "node_latencies_ms": latencies_ms,
            "probe_latencies_ms": probe_latencies_ms,
            "confirmed_nodes": confirmed_nodes,
            "total_propagation_ms": total_propagation_ms,
            "nodes_updated": nodes_updated,
            "nodes_offline": nodes_offline
        }

    def close(self) -> None:
        """Shut down authority and node resources."""
        self.authority.close()
        for node in self.nodes.values():
            node.close()
