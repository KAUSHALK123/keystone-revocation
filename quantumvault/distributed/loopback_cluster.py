"""Optional independent multi-process local-IPC distributed security cluster.

Distinction from ClusterCoordinator (simulated_in_process):
- Spawns 3 independent OS worker processes (node-a, node-b, node-c).
- Each node owns its own separate persistent SQLite database file (`<base>/<node_id>/quantumvault.db`).
- Control & epoch propagation occur over authenticated local loopback TCP JSON-lines IPC
  rather than relying on shared in-memory objects or a shared SQLite DB.
"""
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
from typing import Any

from quantumvault.distributed.authority import SecurityAuthority

_NODE_SERVER_SCRIPT = r"""
import hashlib
import hmac
import json
from pathlib import Path
import socketserver
import sys
import time
from quantumvault.core.service import QuantumVaultService
from quantumvault.storage.db import transaction

STATE_DIR = Path(sys.argv[1])
NODE_ID = sys.argv[2]
IPC_SECRET = sys.argv[3].encode("utf-8")
PORT_FILE = Path(sys.argv[4])
REQUIRE_SYNC_ON_BOOT = (len(sys.argv) > 5 and sys.argv[5] == "--require-sync")

STATE_DIR.mkdir(parents=True, exist_ok=True)
SVC = QuantumVaultService(state_dir=STATE_DIR)

NODE_STATE = {
    "node_id": NODE_ID,
    "epoch": int(SVC.app_state.get("node_epoch") or 1),
    "active_key_version": SVC.app_state.get("active_key_version") or "v1",
    "authority_reachable": not REQUIRE_SYNC_ON_BOOT,
    "online": True,
    "last_heartbeat": 0.0 if REQUIRE_SYNC_ON_BOOT else time.time(),
    "heartbeat_ttl": 10.0,
}
RUNNING = [True]

def _load_persisted_revocations() -> set[tuple[str, str]]:
    return {(r["actor_id"], r["entity_type"]) for r in SVC.revocations.list_all()}

def _verify_mac(msg: dict) -> bool:
    sig = msg.get("hmac", "")
    body = {k: v for k, v in msg.items() if k != "hmac"}
    expected = hmac.new(IPC_SECRET, json.dumps(body, sort_keys=True).encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(str(sig), expected)

def _is_healthy() -> bool:
    if not NODE_STATE["online"] or not NODE_STATE["authority_reachable"]:
        return False
    return (time.time() - NODE_STATE["last_heartbeat"]) <= NODE_STATE["heartbeat_ttl"]

class NodeHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        raw = self.rfile.readline(1024 * 1024)
        if not raw:
            return
        try:
            msg = json.loads(raw.decode("utf-8"))
        except Exception:
            self.wfile.write((json.dumps({"ok": False, "error": "invalid_json"}) + "\n").encode("utf-8"))
            return

        if not _verify_mac(msg):
            self.wfile.write((json.dumps({"ok": False, "error": "invalid_ipc_hmac"}) + "\n").encode("utf-8"))
            return

        cmd = msg.get("cmd")
        res = {"ok": True}

        if cmd == "ping":
            res = {"ok": True, "node_id": NODE_ID, "epoch": NODE_STATE["epoch"], "healthy": _is_healthy()}

        elif cmd == "setup":
            res = SVC.setup(
                owners=msg.get("owners", {}),
                contents=msg.get("contents", {}),
                disabled=msg.get("disabled", []),
                key_material=msg.get("key_material", "mp-seed"),
            )
            with transaction(SVC.conn):
                SVC.app_state.set("node_epoch", str(NODE_STATE["epoch"]))
                SVC.app_state.set("active_key_version", "v1")

        elif cmd == "set_fault":
            if "online" in msg:
                NODE_STATE["online"] = bool(msg["online"])
            if "authority_reachable" in msg:
                NODE_STATE["authority_reachable"] = bool(msg["authority_reachable"])
            if "stale_heartbeat" in msg and msg["stale_heartbeat"]:
                NODE_STATE["last_heartbeat"] = time.time() - 60.0
            if msg.get("refresh_heartbeat"):
                NODE_STATE["last_heartbeat"] = time.time()
            res = {"ok": True, "healthy": _is_healthy(), "online": NODE_STATE["online"], "authority_reachable": NODE_STATE["authority_reachable"]}

        elif cmd == "sync":
            incoming_epoch = int(msg["epoch"])
            if incoming_epoch < NODE_STATE["epoch"]:
                res = {"ok": True, "ignored_stale_epoch": True, "epoch": NODE_STATE["epoch"]}
            else:
                revs = msg.get("revocations", [])
                active_key = msg.get("active_key_version", "v1")
                with transaction(SVC.conn):
                    for entity_id, entity_type in revs:
                        SVC.revocations.revoke(entity_id, entity_type=entity_type, reason="authority_sync")
                        if entity_type == "actor":
                            SVC.identities.disable(entity_id)
                    SVC.app_state.set("node_epoch", str(incoming_epoch))
                    SVC.app_state.set("active_key_version", active_key)
                NODE_STATE["epoch"] = incoming_epoch
                NODE_STATE["active_key_version"] = active_key
                NODE_STATE["authority_reachable"] = True
                NODE_STATE["online"] = True
                NODE_STATE["last_heartbeat"] = time.time()
                res = {"ok": True, "epoch": NODE_STATE["epoch"], "active_key_version": active_key, "revocations_count": len(revs)}

        elif cmd == "apply_revocation":
            incoming_epoch = int(msg["epoch"])
            entity_id = msg["entity_id"]
            entity_type = msg.get("entity_type", "actor")
            if incoming_epoch < NODE_STATE["epoch"]:
                res = {"ok": True, "ignored_stale_epoch": True, "epoch": NODE_STATE["epoch"]}
            else:
                with transaction(SVC.conn):
                    SVC.revocations.revoke(entity_id, entity_type=entity_type, reason="ipc_broadcast")
                    if entity_type == "actor":
                        SVC.identities.disable(entity_id)
                    SVC.app_state.set("node_epoch", str(incoming_epoch))
                NODE_STATE["epoch"] = incoming_epoch
                NODE_STATE["last_heartbeat"] = time.time()
                res = {"ok": True, "epoch": NODE_STATE["epoch"], "applied": entity_id}

        elif cmd == "read":
            actor = msg["actor"]
            asset = msg["asset"]
            req_id = msg["request_id"]
            if not _is_healthy():
                try:
                    with transaction(SVC.conn):
                        SVC.audit_logger.log_decision(req_id, actor, "read", asset, "deny", "node_offline_fail_closed")
                except Exception:
                    pass
                res = {"decision": "deny", "rule": "node_offline_fail_closed", "epoch": NODE_STATE["epoch"]}
            elif SVC.revocations.is_revoked(actor, "actor"):
                try:
                    with transaction(SVC.conn):
                        SVC.audit_logger.log_decision(req_id, actor, "read", asset, "deny", "revoked_actor")
                except Exception:
                    pass
                res = {"decision": "deny", "rule": "revoked_actor", "epoch": NODE_STATE["epoch"]}
            else:
                out = SVC.read(actor=actor, asset=asset, request_id=req_id)
                out["epoch"] = NODE_STATE["epoch"]
                res = out

        elif cmd == "status":
            res = {
                "node_id": NODE_ID,
                "epoch": NODE_STATE["epoch"],
                "active_key_version": NODE_STATE["active_key_version"],
                "healthy": _is_healthy(),
                "online": NODE_STATE["online"],
                "authority_reachable": NODE_STATE["authority_reachable"],
                "db_path": str(SVC.db_path),
                "revocations": sorted([list(x) for x in _load_persisted_revocations()]),
            }

        elif cmd == "shutdown":
            self.wfile.write((json.dumps({"ok": True, "shutting_down": True}) + "\n").encode("utf-8"))
            self.wfile.flush()
            RUNNING[0] = False
            return

        else:
            res = {"ok": False, "error": f"unknown_cmd:{cmd}"}

        self.wfile.write((json.dumps(res) + "\n").encode("utf-8"))
        self.wfile.flush()

class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

with ReusableTCPServer(("127.0.0.1", 0), NodeHandler) as srv:
    srv.timeout = 0.05
    port = srv.server_address[1]
    PORT_FILE.write_text(str(port), encoding="utf-8")
    try:
        while RUNNING[0]:
            srv.handle_request()
    finally:
        SVC.close()
"""


class LoopbackIPCCluster:
    """Orchestrates 1 SecurityAuthority + 3 independent OS service-node processes
    over loopback TCP IPC with separate per-node SQLite WAL databases.
    """

    cluster_mode = "independent_multiprocess_local_ipc"

    def __init__(self, base_dir: Path, node_ids: tuple[str, ...] = ("node-a", "node-b", "node-c")):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.auth_dir = self.base_dir / "authority"
        self.auth_dir.mkdir(parents=True, exist_ok=True)
        self.authority = SecurityAuthority(state_dir=self.auth_dir)
        self.ipc_secret = secrets.token_hex(32)
        self.node_ids = list(node_ids)
        self.procs: dict[str, subprocess.Popen] = {}
        self.ports: dict[str, int] = {}
        self.start_all()

    def _sign(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = {k: v for k, v in payload.items() if k != "hmac"}
        sig = hmac.new(
            self.ipc_secret.encode("utf-8"),
            json.dumps(body, sort_keys=True).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        signed = dict(body)
        signed["hmac"] = sig
        return signed

    def _rpc(self, node_id: str, payload: dict[str, Any], timeout: float = 5.0) -> dict[str, Any]:
        port = self.ports.get(node_id)
        if not port:
            raise RuntimeError(f"Node '{node_id}' is not running")
        wire = (json.dumps(self._sign(payload)) + "\n").encode("utf-8")
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
            sock.sendall(wire)
            chunks: list[bytes] = []
            while True:
                buf = sock.recv(65536)
                if not buf:
                    break
                chunks.append(buf)
                if b"\n" in buf:
                    break
        line = b"".join(chunks).decode("utf-8").splitlines()[0]
        return json.loads(line)

    def start_node(self, node_id: str, timeout: float = 10.0, require_sync: bool = False) -> None:
        node_dir = self.base_dir / node_id
        node_dir.mkdir(parents=True, exist_ok=True)
        port_file = node_dir / f"{node_id}.port"
        if port_file.exists():
            port_file.unlink()
        cmd = [sys.executable, "-B", "-c", _NODE_SERVER_SCRIPT, str(node_dir), node_id, self.ipc_secret, str(port_file)]
        if require_sync:
            cmd.append("--require-sync")
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.procs[node_id] = proc
        deadline = time.perf_counter() + timeout
        while time.perf_counter() < deadline:
            if port_file.exists():
                txt = port_file.read_text(encoding="utf-8").strip()
                if txt:
                    self.ports[node_id] = int(txt)
                    ping = self._rpc(node_id, {"cmd": "ping"})
                    if ping.get("ok"):
                        return
            if proc.poll() is not None:
                raise RuntimeError(f"Worker process '{node_id}' exited early (rc={proc.returncode})")
            time.sleep(0.03)
        raise TimeoutError(f"Timed out waiting for multi-process node '{node_id}'")

    def start_all(self) -> None:
        for nid in self.node_ids:
            self.start_node(nid)

    def setup_all(self, owners: dict[str, str], contents: dict[str, str],
                  disabled: list[str], key_material: str) -> None:
        for nid in self.node_ids:
            self._rpc(nid, {
                "cmd": "setup",
                "owners": owners,
                "contents": contents,
                "disabled": disabled,
                "key_material": key_material,
            })

    def send_raw_ipc(self, node_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._rpc(node_id, payload)

    def read(self, node_id: str, actor: str, asset: str, request_id: str) -> dict[str, Any]:
        return self._rpc(node_id, {"cmd": "read", "actor": actor, "asset": asset, "request_id": request_id})

    def status(self, node_id: str) -> dict[str, Any]:
        return self._rpc(node_id, {"cmd": "status"})

    def set_fault(self, node_id: str, **kwargs: Any) -> dict[str, Any]:
        payload = {"cmd": "set_fault", **kwargs}
        return self._rpc(node_id, payload)

    def sync_node(self, node_id: str) -> dict[str, Any]:
        epoch = self.authority.get_current_epoch()
        revs = sorted([list(x) for x in self.authority.get_all_revocations()])
        active_key = self.authority.get_active_key_version()
        return self._rpc(node_id, {
            "cmd": "sync",
            "epoch": epoch,
            "active_key_version": active_key,
            "revocations": revs,
        })

    def kill_node(self, node_id: str) -> None:
        proc = self.procs.get(node_id)
        if proc and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5.0)
        self.ports.pop(node_id, None)

    def restart_node(self, node_id: str, auto_sync: bool = False) -> None:
        self.kill_node(node_id)
        self.start_node(node_id, require_sync=not auto_sync)
        if auto_sync:
            self.sync_node(node_id)

    def broadcast_revocation(self, entity_id: str, entity_type: str = "actor",
                             reason: str = "multiprocess_revocation") -> dict[str, Any]:
        t_auth = time.perf_counter()
        auth_rec = self.authority.issue_revocation(entity_id, entity_type=entity_type, reason=reason)
        auth_commit_ms = round((time.perf_counter() - t_auth) * 1000.0, 4)

        t_prop_start = time.perf_counter()
        node_latencies_ms: dict[str, float] = {}
        denial_latencies_ms: dict[str, float] = {}
        confirmed_nodes: list[str] = []

        for nid in self.node_ids:
            proc = self.procs.get(nid)
            if not proc or proc.poll() is not None:
                node_latencies_ms[nid] = -1.0
                denial_latencies_ms[nid] = -1.0
                continue
            try:
                st = self.status(nid)
                if not st.get("healthy"):
                    node_latencies_ms[nid] = -1.0
                    denial_latencies_ms[nid] = -1.0
                    continue
                t_n0 = time.perf_counter()
                self._rpc(nid, {
                    "cmd": "apply_revocation",
                    "epoch": auth_rec["epoch"],
                    "entity_id": entity_id,
                    "entity_type": entity_type,
                })
                t_n1 = time.perf_counter()
                node_latencies_ms[nid] = round((t_n1 - t_n0) * 1000.0, 4)

                probe = self.read(nid, entity_id, "probe-asset", f"mp-probe-{nid}-{time.time_ns()}")
                t_n2 = time.perf_counter()
                denial_latencies_ms[nid] = round((t_n2 - t_n1) * 1000.0, 4)
                if probe.get("decision") == "deny":
                    confirmed_nodes.append(nid)
            except Exception:
                node_latencies_ms[nid] = -1.0
                denial_latencies_ms[nid] = -1.0

        total_prop_ms = round((time.perf_counter() - t_prop_start) * 1000.0, 4)
        return {
            "cluster_mode": self.cluster_mode,
            "epoch": auth_rec["epoch"],
            "entity_id": entity_id,
            "auth_commit_latency_ms": auth_commit_ms,
            "node_latencies_ms": node_latencies_ms,
            "denial_enforcement_latencies_ms": denial_latencies_ms,
            "confirmed_nodes": confirmed_nodes,
            "total_propagation_ms": total_prop_ms,
        }

    def close(self) -> None:
        for nid in list(self.node_ids):
            proc = self.procs.get(nid)
            if proc and proc.poll() is None:
                try:
                    self._rpc(nid, {"cmd": "shutdown"}, timeout=1.0)
                    proc.wait(timeout=2.0)
                except Exception:
                    self.kill_node(nid)
        self.authority.close()
