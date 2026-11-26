"""Messaging session lifecycle, forward secrecy teardown, and resumption policy."""
import sqlite3
from typing import Any

from quantumvault.core.errors import SecurityPolicyError
from quantumvault.messaging.e2ee import MessageCipher
from quantumvault.messaging.handshake import zeroize_bytes
from quantumvault.messaging.replay import ReplayProtector


class MessagingSession:
    """Manages an active bi-directional forward-secure messaging session."""

    def __init__(self, session_id: str,
                 local_actor_id: str, local_device_id: str,
                 remote_actor_id: str, remote_device_id: str,
                 k_send: bytes, k_recv: bytes,
                 conn: sqlite3.Connection | None = None):
        self.session_id = session_id
        self.local_actor_id = local_actor_id
        self.local_device_id = local_device_id
        self.remote_actor_id = remote_actor_id
        self.remote_device_id = remote_device_id

        # Ephemeral directional keys
        self._k_send = bytearray(k_send)
        self._k_recv = bytearray(k_recv)

        self.send_seq = 0
        self.replay_protector = ReplayProtector(conn=conn)
        self.is_active = True

        self.cipher_send = MessageCipher(
            key=bytes(self._k_send),
            session_id=session_id,
            sender_id=local_actor_id,
            sender_device=local_device_id,
            recipient_id=remote_actor_id,
            recipient_device=remote_device_id
        )

        self.cipher_recv = MessageCipher(
            key=bytes(self._k_recv),
            session_id=session_id,
            sender_id=remote_actor_id,
            sender_device=remote_device_id,
            recipient_id=local_actor_id,
            recipient_device=local_device_id
        )

    def send_message(self, plaintext: str | bytes) -> dict[str, Any]:
        """Encrypt outgoing message with auto-incrementing sequence number."""
        if not self.is_active:
            raise SecurityPolicyError("Cannot send message on a closed or terminated session")
        self.send_seq += 1
        return self.cipher_send.encrypt_message(plaintext, sequence_num=self.send_seq)

    def receive_message(self, envelope: dict[str, Any]) -> bytes:
        """Validate against replay attacks, authenticate, and decrypt incoming envelope."""
        if not self.is_active:
            raise SecurityPolicyError("Cannot receive message on a closed or terminated session")

        if envelope.get("session_id") != self.session_id:
            raise SecurityPolicyError("Session binding mismatch on incoming message")
        if envelope.get("sender_id") != self.remote_actor_id or envelope.get("recipient_id") != self.local_actor_id:
            raise SecurityPolicyError("Peer identity binding mismatch on incoming message")

        # 1. Pre-check replay freshness without mutating replay cache yet
        self.replay_protector.check_freshness(
            message_id=envelope["message_id"],
            sequence_num=envelope["sequence_num"]
        )

        # 2. Authenticated decryption (raises CryptoError if tampered; replay cache stays clean)
        plaintext = self.cipher_recv.decrypt_message(envelope)

        # 3. Commit to replay cache only after AEAD authentication succeeds
        self.replay_protector.commit_seen(
            message_id=envelope["message_id"],
            session_id=envelope["session_id"],
            sequence_num=envelope["sequence_num"]
        )
        return plaintext

    def close(self) -> None:
        """Explicitly destroy session and zeroize all ephemeral encryption keys in volatile RAM."""
        zeroize_bytes(self._k_send)
        zeroize_bytes(self._k_recv)
        self.is_active = False

    @staticmethod
    def resume_session(*args: Any, **kwargs: Any) -> None:
        """Explicit policy enforcement: Session resumption is strictly prohibited."""
        raise SecurityPolicyError(
            "Session resumption is explicitly unsupported by QuantumVault policy: "
            "To preserve post-quantum forward secrecy against credential leakage, "
            "every session requires a fresh, authenticated ML-KEM-768 ephemeral key exchange."
        )
