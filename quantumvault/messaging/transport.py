"""Chunked message segmentation, out-of-order reassembly, and retransmission protocol."""
from __future__ import annotations
import hashlib
from typing import Any, Tuple

from quantumvault.core.errors import CryptoError


class ChunkedTransport:
    """Segments payloads into bounded frames and safely reassembles out-of-order chunks."""

    MAX_PAYLOAD_BYTES = 16 * 1024 * 1024  # 16 MiB bounded memory cap
    MAX_CHUNKS = 16384

    def __init__(self, chunk_size: int = 1024):
        if chunk_size <= 0:
            raise CryptoError("chunk_size must be positive")
        self.chunk_size = chunk_size

    def segment_payload(self, message_id: str, payload: bytes) -> list[dict[str, Any]]:
        """Segment raw payload bytes into bounded chunks with individual and overall integrity hashes."""
        total_len = len(payload)
        if total_len > self.MAX_PAYLOAD_BYTES:
            raise CryptoError(f"Payload size {total_len} exceeds maximum limit of {self.MAX_PAYLOAD_BYTES} bytes")
        if total_len == 0:
            chunks_data = [b""]
        else:
            chunks_data = [payload[i:i + self.chunk_size] for i in range(0, total_len, self.chunk_size)]

        total_chunks = len(chunks_data)
        if total_chunks > self.MAX_CHUNKS:
            raise CryptoError(f"Chunk count {total_chunks} exceeds maximum limit of {self.MAX_CHUNKS}")
        overall_hash = hashlib.sha256(payload).hexdigest()

        chunk_frames: list[dict[str, Any]] = []
        for idx, chunk in enumerate(chunks_data):
            chunk_frames.append({
                "message_id": message_id,
                "chunk_index": idx,
                "total_chunks": total_chunks,
                "chunk_hash": hashlib.sha256(chunk).hexdigest(),
                "overall_hash": overall_hash,
                "payload": chunk
            })

        return chunk_frames

    def reassemble(self, chunks: list[dict[str, Any]]) -> Tuple[bool, bytes | None, list[int]]:
        """Reassemble received chunks into complete payload.
        
        Returns:
            (is_complete: bool, assembled_bytes: bytes | None, missing_indexes: list[int])
        """
        if not chunks:
            return False, None, []

        total_chunks = chunks[0]["total_chunks"]
        overall_hash = chunks[0]["overall_hash"]
        message_id = chunks[0]["message_id"]

        if not isinstance(total_chunks, int) or total_chunks <= 0 or total_chunks > self.MAX_CHUNKS:
            raise CryptoError(f"Invalid total_chunks value: {total_chunks}")

        by_index: dict[int, dict[str, Any]] = {}
        for c in chunks:
            if c.get("message_id") != message_id:
                raise CryptoError(f"Cross-message chunk substitution rejected: expected {message_id}, got {c.get('message_id')}")
            if c.get("total_chunks") != total_chunks or c.get("overall_hash") != overall_hash:
                raise CryptoError("Inconsistent chunk metadata across message frames")
            idx = c.get("chunk_index")
            if not isinstance(idx, int) or idx < 0 or idx >= total_chunks:
                raise CryptoError(f"Out-of-bounds chunk index {idx} for total_chunks={total_chunks}")
            # Validate individual chunk hash
            if hashlib.sha256(c["payload"]).hexdigest() != c["chunk_hash"]:
                raise CryptoError(f"Corrupted chunk payload at index {idx}")
            if idx in by_index:
                if by_index[idx]["chunk_hash"] != c["chunk_hash"]:
                    raise CryptoError(f"Conflicting duplicate chunk at index {idx}")
                continue
            by_index[idx] = c

        # Determine missing chunks
        missing: list[int] = []
        for i in range(total_chunks):
            if i not in by_index:
                missing.append(i)

        if missing:
            return False, None, missing

        # Reassemble in strict index order
        assembled = b"".join(by_index[i]["payload"] for i in range(total_chunks))
        if hashlib.sha256(assembled).hexdigest() != overall_hash:
            raise CryptoError("Reassembled payload failed overall integrity check")

        return True, assembled, []
