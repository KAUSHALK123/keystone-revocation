"""Independent worker process runner for crash resilience and process termination testing."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

from quantumvault.config import get_db_path, get_state_dir


WORKER_SCRIPT = """
import sys
import time
import json
from pathlib import Path
from quantumvault.core.service import QuantumVaultService

state_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else None
node_id = sys.argv[2] if len(sys.argv) > 2 else "worker-01"
service = QuantumVaultService(state_dir=state_dir)

ready_file = state_dir / f"{node_id}.ready"
ready_file.write_text("ready", encoding="utf-8")

heartbeat_file = state_dir / f"{node_id}.heartbeat"

try:
    while True:
        heartbeat_file.write_text(str(time.time()), encoding="utf-8")
        time.sleep(0.5)
except KeyboardInterrupt:
    pass
"""


class ProcessNode:
    """Manages an isolated OS process running a QuantumVault service node,
    supporting clean termination, abrupt kill (SIGKILL/TerminateProcess),
    and crash recovery testing.
    """

    def __init__(self, node_id: str, state_dir: Path | None = None):
        self.node_id = node_id
        self.state_dir = state_dir or get_state_dir()
        self.process: subprocess.Popen | None = None
        self.ready_file = self.state_dir / f"{node_id}.ready"
        self.heartbeat_file = self.state_dir / f"{node_id}.heartbeat"

    def start(self, timeout_seconds: float = 10.0) -> bool:
        """Spawn independent worker process and await readiness."""
        self.state_dir.mkdir(parents=True, exist_ok=True)
        if self.ready_file.exists():
            self.ready_file.unlink()

        # Start python process running inline worker
        cmd = [
            sys.executable,
            "-c",
            WORKER_SCRIPT,
            str(self.state_dir),
            self.node_id
        ]

        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        start_time = time.time()
        while time.time() - start_time < timeout_seconds:
            if self.ready_file.exists():
                return True
            if self.process.poll() is not None:
                # Process exited prematurely
                return False
            time.sleep(0.1)

        return False

    def is_alive(self) -> bool:
        """Return True if process is running."""
        if not self.process:
            return False
        return self.process.poll() is None

    def last_heartbeat_time(self) -> float | None:
        """Read latest heartbeat timestamp from disk."""
        if self.heartbeat_file.exists():
            try:
                return float(self.heartbeat_file.read_text(encoding="utf-8").strip())
            except Exception:
                return None
        return None

    def _close_pipes(self) -> None:
        if not self.process:
            return
        for stream in (self.process.stdout, self.process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    def terminate(self, timeout_seconds: float = 5.0) -> int | None:
        """Gracefully terminate worker process."""
        if not self.process:
            return None
        if self.process.poll() is not None:
            self._close_pipes()
            return self.process.poll()
        self.process.terminate()
        try:
            rc = self.process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            self.process.kill()
            rc = self.process.wait()
        self._close_pipes()
        return rc

    def kill(self) -> int:
        """Abruptly terminate process (simulating ungraceful crash/power cut)."""
        if not self.process:
            return 0
        self.process.kill()
        rc = self.process.wait()
        self._close_pipes()
        return rc

    def cleanup(self) -> None:
        """Ensure process is killed and files cleaned."""
        if self.process and self.process.poll() is None:
            self.kill()
        self._close_pipes()
        for f in [self.ready_file, self.heartbeat_file]:
            if f.exists():
                try:
                    f.unlink()
                except OSError:
                    pass
