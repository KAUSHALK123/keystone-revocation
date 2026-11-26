"""Cryptographic audit log verifier detecting modifications, deletions, injections, and truncations."""
from __future__ import annotations
import sqlite3
from typing import Any

from quantumvault.audit.checkpoints import CheckpointManager
from quantumvault.audit.logger import GENESIS_PREV_HASH, compute_entry_hash
from quantumvault.storage.repositories import AuditRepository


class AuditLogVerifier:
    """Independent auditor verifying full chain integrity and checkpoint consistency."""

    def __init__(self, conn: sqlite3.Connection, secret_key: bytes | None = None,
                 external_file_path: Any = None):
        self.conn = conn
        self.audit_repo = AuditRepository(conn)
        self.chk_mgr = CheckpointManager(conn, secret_key=secret_key, external_file_path=external_file_path)

    def verify(self) -> dict[str, Any]:
        """Perform full end-to-end cryptographic verification of the audit store.
        
        Returns a structured report:
            - status: 'valid' | 'tampered'
            - total_records: count
            - verified_records: count
            - first_inconsistency: None | dict
            - checkpoints_verified: count
            - checkpoints_valid: bool
        """
        chain = self.audit_repo.get_chain(start_seq=1)
        total_records = len(chain)

        if total_records == 0:
            # Check if any checkpoints exist while records were wiped
            latest_chk = self.chk_mgr.get_latest_checkpoint()
            if latest_chk is not None:
                return {
                    "status": "tampered",
                    "total_records": 0,
                    "verified_records": 0,
                    "first_inconsistency": {
                        "error_type": "truncated_log",
                        "sequence_num": 1,
                        "description": f"Audit log was wiped: checkpoint expected at least {latest_chk['sequence_up_to']} records"
                    },
                    "checkpoints_verified": 1,
                    "checkpoints_valid": False
                }
            return {
                "status": "valid",
                "total_records": 0,
                "verified_records": 0,
                "first_inconsistency": None,
                "checkpoints_verified": 0,
                "checkpoints_valid": True
            }

        prev_entry_hash = GENESIS_PREV_HASH
        expected_seq = 1

        # 1. Verify Hash Chain Continuity and Entry Hashes
        for idx, row in enumerate(chain):
            seq = row["sequence_num"]

            # Check sequence continuity
            if seq != expected_seq:
                return {
                    "status": "tampered",
                    "total_records": total_records,
                    "verified_records": idx,
                    "first_inconsistency": {
                        "sequence_num": seq,
                        "request_id": row["request_id"],
                        "error_type": "sequence_gap",
                        "expected": expected_seq,
                        "actual": seq,
                        "description": f"Sequence gap detected: expected {expected_seq}, found {seq}"
                    },
                    "checkpoints_verified": 0,
                    "checkpoints_valid": False
                }

            # Check link to previous block
            if row["prev_hash"] != prev_entry_hash:
                return {
                    "status": "tampered",
                    "total_records": total_records,
                    "verified_records": idx,
                    "first_inconsistency": {
                        "sequence_num": seq,
                        "request_id": row["request_id"],
                        "error_type": "broken_chain",
                        "expected": prev_entry_hash,
                        "actual": row["prev_hash"],
                        "description": "Previous hash link is broken; an intermediate event was deleted or reordered"
                    },
                    "checkpoints_verified": 0,
                    "checkpoints_valid": False
                }

            # Recompute entry hash
            computed_hash = compute_entry_hash(
                prev_hash=row["prev_hash"],
                request_id=row["request_id"],
                event_time_utc=row["event_time_utc"],
                actor_id=row["actor_id"],
                op=row["op"],
                asset_id=row["asset_id"],
                decision=row["decision"],
                rule=row["rule"]
            )

            if row["entry_hash"] != computed_hash:
                return {
                    "status": "tampered",
                    "total_records": total_records,
                    "verified_records": idx,
                    "first_inconsistency": {
                        "sequence_num": seq,
                        "request_id": row["request_id"],
                        "error_type": "hash_mismatch",
                        "expected": computed_hash,
                        "actual": row["entry_hash"],
                        "description": "Entry hash mismatch; record fields have been modified after writing"
                    },
                    "checkpoints_verified": 0,
                    "checkpoints_valid": False
                }

            prev_entry_hash = row["entry_hash"]
            expected_seq += 1

        # 2. Verify Checkpoints Against Cumulative Chain
        checkpoints = self.chk_mgr.list_checkpoints()
        chain_by_seq = {r["sequence_num"]: r for r in chain}

        for chk in checkpoints:
            # Verify HMAC signature of checkpoint record
            if not self.chk_mgr.verify_checkpoint(chk):
                return {
                    "status": "tampered",
                    "total_records": total_records,
                    "verified_records": total_records,
                    "first_inconsistency": {
                        "sequence_num": chk["sequence_up_to"],
                        "checkpoint_id": chk["checkpoint_id"],
                        "error_type": "invalid_checkpoint_hmac",
                        "description": "Checkpoint HMAC authentication failed; checkpoint record was tampered with"
                    },
                    "checkpoints_verified": len(checkpoints),
                    "checkpoints_valid": False
                }

            seq_up_to = chk["sequence_up_to"]

            # Truncation check: log does not reach checkpoint sequence
            if seq_up_to > total_records:
                return {
                    "status": "tampered",
                    "total_records": total_records,
                    "verified_records": total_records,
                    "first_inconsistency": {
                        "sequence_num": total_records,
                        "checkpoint_id": chk["checkpoint_id"],
                        "error_type": "truncated_log",
                        "expected": seq_up_to,
                        "actual": total_records,
                        "description": f"Log truncation detected: checkpoint claims {seq_up_to} records, but only {total_records} exist"
                    },
                    "checkpoints_verified": len(checkpoints),
                    "checkpoints_valid": False
                }

            target_row = chain_by_seq.get(seq_up_to)
            if not target_row or target_row["entry_hash"] != chk["cumulative_hash"]:
                return {
                    "status": "tampered",
                    "total_records": total_records,
                    "verified_records": total_records,
                    "first_inconsistency": {
                        "sequence_num": seq_up_to,
                        "checkpoint_id": chk["checkpoint_id"],
                        "error_type": "checkpoint_mismatch",
                        "expected": chk["cumulative_hash"],
                        "actual": target_row["entry_hash"] if target_row else None,
                        "description": f"Cumulative hash at sequence {seq_up_to} does not match checkpoint"
                    },
                    "checkpoints_verified": len(checkpoints),
                    "checkpoints_valid": False
                }

        return {
            "status": "valid",
            "total_records": total_records,
            "verified_records": total_records,
            "first_inconsistency": None,
            "checkpoints_verified": len(checkpoints),
            "checkpoints_valid": True
        }
