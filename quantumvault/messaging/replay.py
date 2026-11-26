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

    def check_and_record(self, message_id: str, session_id: str, sequence_num: int) -> None:
        """Validate that message is not a duplicate or replayed packet, then record it."""
        # 1. In-memory message ID check
        if message_id in self.in_memory_seen_ids:
            raise SecurityPolicyError(f"Replay detected: message ID '{message_id}' already processed")

        # 2. Database persistent check
        if self.replay_repo:
            if self.replay_repo.is_seen(message_id):
                raise SecurityPolicyError(f"Replay detected: message ID '{message_id}' already seen in persistent cache")

        # 3. Sliding window sequence number evaluation
        if sequence_num <= 0:
            raise SecurityPolicyError(f"Invalid sequence number: {sequence_num} must be positive")

        if sequence_num > self.highest_seq:
            # Advance sliding window
            diff = sequence_num - self.highest_seq
            if diff >= self.window_size:
                self.window_bitmap = 1  # Reset window, set current sequence
            else:
                self.window_bitmap = (self.window_bitmap << diff) | 1
            self.highest_seq = sequence_num
        else:
            # Sequence number is less than or equal to highest_seq
            diff = self.highest_seq - sequence_num
            if diff >= self.window_size:
                raise SecurityPolicyError(
                    f"Replay rejected: sequence {sequence_num} is outside acceptable sliding window (highest: {self.highest_seq}, window: {self.window_size})"
                )
            
            # Check if bit at position diff is already 1
            if (self.window_bitmap & (1 << diff)) != 0:
                raise SecurityPolicyError(
                    f"Replay detected: duplicate sequence number {sequence_num} already processed in current window"
                )
            
            # Mark sequence as seen
            self.window_bitmap |= (1 << diff)

        # 4. Record as seen
        self.in_memory_seen_ids.add(message_id)
        if self.replay_repo:
            self.replay_repo.record_seen(message_id, session_id, sequence_num)
