"""Worker process for multi-process distributed node execution.
Receives HMAC-authenticated IPC commands via stdin, enforces fail-closed PEP policies,
and responds via stdout with HMAC-signed responses.
"""
import hashlib
import hmac
import json
from pathlib import Path
import sys
import time
from typing import Any

from quantumvault.core.service import QuantumVaultService
from quantumvault.crypto.pqc_kem import MLKEM768
from quantumvault.iam.device import DeviceManager
from quantumvault.storage.db import transaction


def sign_message(key: bytes, msg: dict[str, Any]) -> str:
    """Compute HMAC-SHA256 signature over canonical representation of message fields."""
    canonical = json.dumps(
        {k: v for k, v in sorted(msg.items()) if k != "signature"},
        separators=(",", ":")
    ).encode("utf-8")
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()


def verify_message(key: bytes, msg: dict[str, Any]) -> bool:
    """Verify HMAC-SHA256 signature on an incoming IPC message."""
    expected = msg.get("signature")
    if not expected:
        return False
    actual = sign_message(key, msg)
    return hmac.compare_digest(actual, expected)


class ProcessWorker:
    def __init__(self, state_dir: Path, node_id: str, ipc_secret: bytes):
        self.state_dir = Path(state_dir)
        self.node_id = node_id
        self.ipc_secret = ipc_secret
        self.service = QuantumVaultService(state_dir=self.state_dir)
        self.pqc = MLKEM768()

        self.status = "online"
        self.current_epoch = 1
        self.cached_revocations: set[tuple[str, str]] = set()
        try:
            for r in self.service.revocations.list_all():
                self.cached_revocations.add((r["actor_id"], r["entity_type"]))
        except Exception:
            pass
        self.authority_connected = True
        self.last_heartbeat = time.time()
        self.heartbeat_threshold_seconds = 5.0

        # Persistent IPC replay cache: survives process restarts and crash cycles
        self.seen_messages: set[str] = set()
        try:
            self.service.conn.execute("""
                CREATE TABLE IF NOT EXISTS ipc_seen_messages (
                    msg_id TEXT PRIMARY KEY,
                    seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            self.service.conn.commit()
            rows = self.service.conn.execute("SELECT msg_id FROM ipc_seen_messages").fetchall()
            self.seen_messages = {r[0] for r in rows}
        except Exception:
            pass

    def is_healthy(self) -> bool:
        """Fail-closed health evaluation."""
        if not self.authority_connected or self.status != "online":
            return False
        if time.time() - self.last_heartbeat > self.heartbeat_threshold_seconds:
            return False
        return True

    def handle_command(self, cmd: dict[str, Any]) -> dict[str, Any]:
        """Dispatch HMAC-verified command."""
        op = cmd.get("op")
        msg_id = cmd.get("msg_id", "")
        target = cmd.get("target")
        sender = cmd.get("sender")
        version = cmd.get("version", "1.0")
        timestamp = cmd.get("timestamp")

        # 1. Target node verification
        if target and target != self.node_id and target != "broadcast":
            return {"status": "ignored", "reason": "wrong_target"}

        # 2. Replay protection
        if msg_id:
            if msg_id in self.seen_messages:
                return {"status": "error", "error": "replay_detected"}
            self.seen_messages.add(msg_id)
            try:
                self.service.conn.execute(
                    "INSERT OR IGNORE INTO ipc_seen_messages (msg_id) VALUES (?);", (msg_id,)
                )
                self.service.conn.commit()
            except Exception:
                pass

        # 3. Check epoch bounds
        msg_epoch = cmd.get("epoch")
        if msg_epoch is not None and msg_epoch < self.current_epoch and op != "ping":
            return {"status": "error", "error": "stale_policy_epoch"}

        # 4. Freshness check: reject messages with timestamps > 120s in the future or > 300s in the past
        if timestamp is not None:
            now = time.time()
            if timestamp > now + 120.0 or timestamp < now - 300.0:
                return {"status": "error", "error": "timestamp_out_of_bounds"}

        # Refresh heartbeat on valid authority message
        self.last_heartbeat = time.time()

        if op == "ping":
            return {"status": "ok", "node_id": self.node_id, "healthy": self.is_healthy(), "epoch": self.current_epoch}

        elif op == "sync":
            new_epoch = cmd.get("epoch", self.current_epoch)
            rev_list = cmd.get("revocations", [])
            self.cached_revocations = {(r[0], r[1]) for r in rev_list}
            try:
                with transaction(self.service.conn):
                    for ent_id, ent_type in self.cached_revocations:
                        self.service.revocations.revoke(
                            ent_id, entity_type=ent_type, reason="cluster_sync_revocation"
                        )
            except Exception:
                pass
            if new_epoch >= self.current_epoch:
                self.current_epoch = new_epoch
            return {"status": "ok", "epoch": self.current_epoch, "revocations_count": len(self.cached_revocations)}

        elif op == "revoke":
            entity_id = cmd.get("entity_id")
            entity_type = cmd.get("entity_type", "actor")
            new_epoch = cmd.get("epoch", self.current_epoch)
            if entity_id:
                self.cached_revocations.add((entity_id, entity_type))
                try:
                    with transaction(self.service.conn):
                        self.service.revocations.revoke(
                            entity_id, entity_type=entity_type, reason="cluster_ipc_revocation"
                        )
                except Exception:
                    pass
            if new_epoch >= self.current_epoch:
                self.current_epoch = new_epoch
            return {"status": "ok", "entity_id": entity_id, "epoch": self.current_epoch}

        elif op == "partition":
            self.status = "offline"
            self.authority_connected = False
            return {"status": "ok", "node_id": self.node_id, "state": "offline"}

        elif op == "reconnect":
            self.status = "online"
            self.authority_connected = True
            self.last_heartbeat = time.time()
            return {"status": "ok", "node_id": self.node_id, "state": "online"}

        elif op == "read":
            actor = cmd.get("actor", "")
            asset = cmd.get("asset", "")
            req_id = cmd.get("request_id", "")
            device_id = cmd.get("device_id")

            # PEP local cache & fail-closed check
            if not self.is_healthy():
                return {"decision": "deny", "rule": "node_offline_fail_closed"}

            if (actor, "actor") in self.cached_revocations:
                return {"decision": "deny", "rule": "actor_revoked_cached"}

            if device_id and (device_id, "device") in self.cached_revocations:
                return {"decision": "deny", "rule": "device_revoked_cached"}

            return self.service.read(actor=actor, asset=asset, request_id=req_id)

        elif op == "protected_read":
            actor = cmd.get("actor", "")
            asset = cmd.get("asset", "")
            challenge = cmd.get("challenge", "")
            public_key = cmd.get("public_key", "")
            device_id = cmd.get("device_id")

            if not self.is_healthy():
                return {"decision": "deny", "rule": "node_offline_fail_closed"}

            if (actor, "actor") in self.cached_revocations:
                return {"decision": "deny", "rule": "actor_revoked_cached"}

            if device_id and (device_id, "device") in self.cached_revocations:
                return {"decision": "deny", "rule": "device_revoked_cached"}

            return self.service.protected_read(
                actor=actor,
                asset=asset,
                challenge=challenge,
                public_key=public_key
            )

        return {"status": "error", "error": f"unknown_operation:{op}"}

    def run(self):
        """Main event loop over stdin."""
        ready_file = self.state_dir / f"{self.node_id}.ready"
        ready_file.write_text("ready", encoding="utf-8")

        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                cmd = json.loads(line)
            except Exception:
                err_resp = {"status": "error", "error": "malformed_json"}
                err_resp["signature"] = sign_message(self.ipc_secret, err_resp)
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()
                continue

            # Verify HMAC signature
            if not verify_message(self.ipc_secret, cmd):
                err_resp = {"status": "error", "error": "invalid_ipc_signature"}
                err_resp["signature"] = sign_message(self.ipc_secret, err_resp)
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()
                continue

            res = self.handle_command(cmd)
            res["signature"] = sign_message(self.ipc_secret, res)
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()


def main():
    if len(sys.argv) < 4:
        sys.exit(1)
    state_dir = Path(sys.argv[1])
    node_id = sys.argv[2]
    ipc_secret = sys.argv[3].encode("utf-8")

    worker = ProcessWorker(state_dir, node_id, ipc_secret)
    worker.run()


if __name__ == "__main__":
    main()
