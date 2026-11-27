"""End-to-end authenticated message encryption (AES-256-GCM) with recipient identity binding."""
import base64
from datetime import datetime, timezone
import os
import secrets
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from quantumvault.core.errors import CryptoError
from quantumvault.crypto.aad import construct_message_aad_canonical


def construct_legacy_message_aad(session_id: str, sequence_num: int,
                                 sender_id: str, sender_device: str,
                                 recipient_id: str, recipient_device: str,
                                 timestamp_iso: str) -> bytes:
    """Legacy Associated Authenticated Data (AAD) binding format."""
    return f"quantumvault:msg:v1|{session_id}|{sequence_num}|{sender_id}|{sender_device}|{recipient_id}|{recipient_device}|{timestamp_iso}".encode("utf-8")


def construct_message_aad(session_id: str, sequence_num: int,
                          sender_id: str, sender_device: str,
                          recipient_id: str, recipient_device: str,
                          timestamp_iso: str) -> bytes:
    """Construct canonical Associated Authenticated Data (AAD) binding message context."""
    return construct_message_aad_canonical(
        session_id=session_id,
        sequence_num=sequence_num,
        sender_id=sender_id,
        sender_device=sender_device,
        recipient_id=recipient_id,
        recipient_device=recipient_device,
        timestamp_iso=timestamp_iso
    )


class MessageCipher:
    """AEAD message cipher enforcing strict session and peer identity binding."""

    def __init__(self, key: bytes, session_id: str,
                 sender_id: str, sender_device: str,
                 recipient_id: str, recipient_device: str):
        if len(key) != 32:
            raise CryptoError("MessageCipher key must be exactly 32 bytes (AES-256)")
        self.key = key
        self.session_id = session_id
        self.sender_id = sender_id
        self.sender_device = sender_device
        self.recipient_id = recipient_id
        self.recipient_device = recipient_device
        self._aesgcm = AESGCM(key)

    def encrypt_message(self, plaintext: str | bytes, sequence_num: int,
                        timestamp_iso: str | None = None) -> dict[str, Any]:
        """Encrypt message payload under AES-256-GCM with context-bound AAD."""
        ts = timestamp_iso or datetime.now(timezone.utc).isoformat()
        aad = construct_message_aad(
            session_id=self.session_id,
            sequence_num=sequence_num,
            sender_id=self.sender_id,
            sender_device=self.sender_device,
            recipient_id=self.recipient_id,
            recipient_device=self.recipient_device,
            timestamp_iso=ts
        )

        nonce = secrets.token_bytes(12)
        data_bytes = plaintext.encode("utf-8") if isinstance(plaintext, str) else bytes(plaintext)
        
        # AESGCM.encrypt returns ciphertext + 16-byte tag appended
        ct_with_tag = self._aesgcm.encrypt(nonce, data_bytes, aad)
        ciphertext = ct_with_tag[:-16]
        tag = ct_with_tag[-16:]

        message_id = f"msg-{self.session_id}-{sequence_num:06d}"

        return {
            "message_id": message_id,
            "session_id": self.session_id,
            "sequence_num": sequence_num,
            "sender_id": self.sender_id,
            "sender_device": self.sender_device,
            "recipient_id": self.recipient_id,
            "recipient_device": self.recipient_device,
            "timestamp": ts,
            "nonce_b64": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext_b64": base64.b64encode(ciphertext).decode("utf-8"),
            "tag_b64": base64.b64encode(tag).decode("utf-8")
        }

    def decrypt_message(self, envelope: dict[str, Any]) -> bytes:
        """Decrypt and authenticate message envelope, raising CryptoError on tampering."""
        try:
            nonce = base64.b64decode(envelope["nonce_b64"])
            ciphertext = base64.b64decode(envelope["ciphertext_b64"])
            tag = base64.b64decode(envelope["tag_b64"])
            seq_num = envelope["sequence_num"]
            ts = envelope["timestamp"]
        except Exception as e:
            raise CryptoError(f"Malformed message envelope: {e}") from e

        canonical_aad = construct_message_aad_canonical(
            session_id=self.session_id,
            sequence_num=seq_num,
            sender_id=envelope["sender_id"],
            sender_device=envelope["sender_device"],
            recipient_id=envelope["recipient_id"],
            recipient_device=envelope["recipient_device"],
            timestamp_iso=ts
        )

        ct_with_tag = ciphertext + tag
        try:
            plaintext = self._aesgcm.decrypt(nonce, ct_with_tag, canonical_aad)
            return plaintext
        except InvalidTag:
            legacy_aad = construct_legacy_message_aad(
                session_id=self.session_id,
                sequence_num=seq_num,
                sender_id=envelope["sender_id"],
                sender_device=envelope["sender_device"],
                recipient_id=envelope["recipient_id"],
                recipient_device=envelope["recipient_device"],
                timestamp_iso=ts
            )
            try:
                plaintext = self._aesgcm.decrypt(nonce, ct_with_tag, legacy_aad)
                return plaintext
            except InvalidTag as e:
                raise CryptoError("Message authentication failed: AEAD MAC mismatch or tampering detected") from e
