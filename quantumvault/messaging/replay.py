"""Sliding window and persistent replay protection mechanism."""
import sqlite3
from typing import Any

from quantumvault.core.errors import SecurityPolicyError
from quantumvault.storage.repositories import ReplayRepository


class ReplayProtector:
    """Combines a sliding window bitmask with persistent SQLite replay storage
    to defend against network replays, duplicates, and out-of-order retransmission attacks.
    """

    def __init__(self, conn: sqlite3.Connection | None = None, window_size: int = 64):
        self.conn = conn
        self.replay_repo = ReplayRepository(conn) if conn else None
        self.window_size = window_size
        self.highest_seq = 0
        # Bitmap of received packets relative to highest_seq: bit 0 is highest_seq, bit i is highest_seq - i
        self.window_bitmap = 0
        self.in_memory_seen_ids: set[str] = set()

    def check_freshness(self, message_id: str, sequence_num: int) -> None:
        """Validate replay freshness without mutating state (use before AEAD verification)."""
        if message_id in self.in_memory_seen_ids:
            raise SecurityPolicyError(f"Replay detected: message ID '{message_id}' already processed")

        if self.replay_repo and self.replay_repo.is_seen(message_id):
            raise SecurityPolicyError(f"Replay detected: message ID '{message_id}' already seen in persistent cache")

        if not isinstance(sequence_num, int) or isinstance(sequence_num, bool) or sequence_num <= 0:
            raise SecurityPolicyError(f"Invalid sequence number: {sequence_num} must be positive")

        if sequence_num <= self.highest_seq:
            diff = self.highest_seq - sequence_num
            if diff >= self.window_size:
                raise SecurityPolicyError(
                    f"Replay rejected: sequence {sequence_num} is outside acceptable sliding window (highest: {self.highest_seq}, window: {self.window_size})"
                )
            if (self.window_bitmap & (1 << diff)) != 0:
                raise SecurityPolicyError(
                    f"Replay detected: duplicate sequence number {sequence_num} already processed in current window"
                )

    def commit_seen(self, message_id: str, session_id: str, sequence_num: int) -> None:
        """Record an authenticated message in the sliding window and persistent replay cache."""
        if sequence_num > self.highest_seq:
            diff = sequence_num - self.highest_seq
            if diff >= self.window_size:
                self.window_bitmap = 1
            else:
                self.window_bitmap = (self.window_bitmap << diff) | 1
            self.highest_seq = sequence_num
        else:
            diff = self.highest_seq - sequence_num
            self.window_bitmap |= (1 << diff)

        self.in_memory_seen_ids.add(message_id)
        if self.replay_repo:
            if not self.replay_repo.record_seen(message_id, session_id, sequence_num):
                raise SecurityPolicyError(f"Replay detected during atomic commit: message ID '{message_id}'")

    def check_and_record(self, message_id: str, session_id: str, sequence_num: int) -> None:
        """Validate that message is not a duplicate or replayed packet, then record it."""
        self.check_freshness(message_id, sequence_num)
        self.commit_seen(message_id, session_id, sequence_num)

    def check_and_accept(self, sequence: int = 0, **kwargs: Any) -> bool:
        """Validate sequence freshness and update sliding window, returning True if accepted."""
        seq = sequence or kwargs.get("seq") or kwargs.get("sequence_number") or kwargs.get("seq_num") or kwargs.get("seq_no") or 0
        if not isinstance(seq, int) or isinstance(seq, bool) or seq <= 0:
            return False

        if self.highest_seq == 0:
            self.highest_seq = seq
            self.window_bitmap = 1
            return True

        if seq > self.highest_seq:
            diff = seq - self.highest_seq
            if diff >= self.window_size:
                self.window_bitmap = 1
            else:
                self.window_bitmap = (self.window_bitmap << diff) | 1
            self.highest_seq = seq
            return True

        diff = self.highest_seq - seq
        if diff >= self.window_size:
            return False

        if (self.window_bitmap & (1 << diff)) != 0:
            return False

        self.window_bitmap |= (1 << diff)
        return True
