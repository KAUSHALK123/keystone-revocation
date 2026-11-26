"""Service graph representing authorized service-to-service communication topologies."""
from __future__ import annotations
from typing import Any


DEFAULT_EXPECTED_EDGES = {
    ("portal", "identity"),
    ("portal", "catalog"),
    ("portal", "reports"),
    ("portal", "reports-node-a"),
    ("portal", "reports-node-b"),
    ("admin-console", "identity"),
    ("reports", "catalog"),
}


class ServiceGraph:
    """Tracks expected service edges and detects anomalous cross-service hops."""

    def __init__(self, expected_edges: set[tuple[str, str]] | None = None):
        self.expected_edges: set[tuple[str, str]] = set(expected_edges or DEFAULT_EXPECTED_EDGES)

    def add_expected_edge(self, source: str, target: str) -> None:
        self.expected_edges.add((source, target))

    def remove_expected_edge(self, source: str, target: str) -> None:
        self.expected_edges.discard((source, target))

    def is_expected(self, source: str, target: str) -> bool:
        """Return True if the directed service edge is in the authorized topology."""
        return (source, target) in self.expected_edges

    def get_topology(self) -> list[dict[str, str]]:
        return [{"source": s, "target": t} for s, t in sorted(self.expected_edges)]
