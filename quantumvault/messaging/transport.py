"""Chunked message segmentation, out-of-order reassembly, and retransmission protocol."""
import hashlib
from typing import Any, Tuple

from quantumvault.core.errors import CryptoError


class ChunkedTransport:
    """Segments payloads into bounded frames and safely reassembles out-of-order chunks."""

    def __init__(self, chunk_size: int = 1024):
        self.chunk_size = chunk_size

    def segment_payload(self, message_id: str, payload: bytes) -> list[dict[str, Any]]:
        """Segment raw payload bytes into bounded chunks with individual and overall integrity hashes."""
        total_len = len(payload)
        if total_len == 0:
            chunks_data = [b""]
        else:
            chunks_data = [payload[i:i + self.chunk_size] for i in range(0, total_len, self.chunk_size)]

        total_chunks = len(chunks_data)
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

        by_index: dict[int, dict[str, Any]] = {}
        for c in chunks:
            if c["message_id"] != message_id:
                continue
            idx = c["chunk_index"]
            # Validate individual chunk hash
            if hashlib.sha256(c["payload"]).hexdigest() != c["chunk_hash"]:
                raise CryptoError(f"Corrupted chunk payload at index {idx}")
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
