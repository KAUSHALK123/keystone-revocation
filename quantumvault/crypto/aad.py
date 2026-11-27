"""Canonical, unambiguous Associated Authenticated Data (AAD) encoding.
Uses domain separation tags and length-prefixed framing to prevent boundary-shifting
and ciphertext substitution attacks across identifiers containing delimiters, unicode, or empty values.
"""
from typing import Sequence


def encode_length_prefixed(fields: Sequence[str | bytes], domain_tag: bytes) -> bytes:
    """Construct canonical, unambiguous AAD with domain separation and 4-byte big-endian length prefixes.
    Format: <domain_tag><field_count_2bytes>[<field_len_4bytes><field_bytes>...]
    """
    out = bytearray(domain_tag)
    out.extend(len(fields).to_bytes(2, "big"))
    for field in fields:
        if isinstance(field, str):
            f_bytes = field.encode("utf-8")
        else:
            f_bytes = bytes(field)
        out.extend(len(f_bytes).to_bytes(4, "big"))
        out.extend(f_bytes)
    return bytes(out)


def construct_resource_aad(asset_id: str, owner_id: str) -> bytes:
    """Construct canonical AAD binding an asset to its owner."""
    return encode_length_prefixed([asset_id, owner_id], b"QV_ASSET_v2\x00")


def construct_legacy_resource_aad(asset_id: str, owner_id: str) -> bytes:
    """Legacy AAD format for seamless backward compatibility and migration."""
    return f"{asset_id}:{owner_id}".encode("utf-8")


def construct_key_version_aad(version_id: str) -> bytes:
    """Construct canonical AAD binding a master key version."""
    return encode_length_prefixed([version_id], b"QV_KEY_v2\x00")


def construct_legacy_key_version_aad(version_id: str) -> bytes:
    """Legacy key version AAD format."""
    return f"key_version:{version_id}".encode("utf-8")


def construct_outbox_aad(outbox_id: str, actor_id: str, recipient_id: str) -> bytes:
    """Construct canonical AAD binding offline outbox records."""
    return encode_length_prefixed([outbox_id, actor_id, recipient_id], b"QV_OUTBOX_v2\x00")


def construct_legacy_outbox_aad(outbox_id: str, actor_id: str, recipient_id: str) -> bytes:
    """Legacy outbox AAD format for backward compatibility."""
    return f"outbox:{outbox_id}:{actor_id}:{recipient_id}".encode("utf-8")


def construct_message_aad_canonical(session_id: str, sequence_num: int,
                                    sender_id: str, sender_device: str,
                                    recipient_id: str, recipient_device: str,
                                    timestamp_iso: str) -> bytes:
    """Construct canonical length-prefixed AAD binding message context."""
    return encode_length_prefixed([
        session_id, str(sequence_num), sender_id, sender_device,
        recipient_id, recipient_device, timestamp_iso
    ], b"QV_MSG_v2\x00")
