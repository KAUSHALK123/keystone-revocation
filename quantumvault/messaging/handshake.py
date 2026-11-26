"""Authenticated ephemeral post-quantum key establishment protocol (ML-KEM-768 + ML-DSA-65 / Ed25519)."""
import base64
from datetime import datetime, timezone
import hashlib
import os
import secrets
from typing import Any, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from quantumvault.core.errors import CryptoError, SecurityPolicyError
from quantumvault.crypto.pqc_dsa import MLDSA65
from quantumvault.crypto.pqc_kem import MLKEM768


def zeroize_bytes(b: bytearray | bytes) -> None:
    """Best-effort in-memory zeroization of sensitive key material."""
    if isinstance(b, bytearray):
        for i in range(len(b)):
            b[i] = 0


def verify_peer_signature(peer_pubkey_b64: str, canonical_context: bytes, signature_b64: str) -> bool:
    """Verify peer signature supporting both NIST ML-DSA-65 (1952 bytes) and Ed25519 (32 bytes)."""
    try:
        pk_bytes = base64.b64decode(peer_pubkey_b64.strip(), validate=True)
        sig_bytes = base64.b64decode(signature_b64.strip(), validate=True)
    except Exception:
        return False

    if len(pk_bytes) == 1952:
        try:
            dsa = MLDSA65()
            return dsa.verify(pk_bytes, canonical_context, sig_bytes)
        except Exception:
            return False
    elif len(pk_bytes) == 32:
        try:
            ed_pk = ed25519.Ed25519PublicKey.from_public_bytes(pk_bytes)
            ed_pk.verify(sig_bytes, canonical_context)
            return True
        except Exception:
            return False
    return False


def sign_context(signing_key: bytes | ed25519.Ed25519PrivateKey, canonical_context: bytes) -> str:
    """Sign context using ML-DSA-65 secret key bytes (4032 bytes) or Ed25519 private key."""
    if isinstance(signing_key, ed25519.Ed25519PrivateKey):
        sig = signing_key.sign(canonical_context)
        return base64.b64encode(sig).decode("utf-8")
    elif isinstance(signing_key, (bytes, bytearray)):
        if len(signing_key) == 32:
            ed_sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(signing_key))
            sig = ed_sk.sign(canonical_context)
            return base64.b64encode(sig).decode("utf-8")
        elif len(signing_key) == 4032:
            dsa = MLDSA65()
            sig = dsa.sign(bytes(signing_key), canonical_context)
            return base64.b64encode(sig).decode("utf-8")
    raise CryptoError("Unsupported signing key format for handshake authentication")


def derive_session_keys(shared_secret: bytes, session_id: str,
                        alice_id: str, bob_id: str) -> Tuple[bytes, bytes]:
    """Derive directional 256-bit AES-GCM session keys via HKDF-SHA256:
    (k_alice_to_bob, k_bob_to_alice).
    """
    salt = hashlib.sha256(f"quantumvault:session-salt:{session_id}".encode("utf-8")).digest()
    
    # Alice to Bob
    info_ab = f"quantumvault:key:{session_id}|{alice_id}->{bob_id}".encode("utf-8")
    hkdf_ab = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info_ab
    )
    k_ab = hkdf_ab.derive(shared_secret)

    # Bob to Alice
    info_ba = f"quantumvault:key:{session_id}|{bob_id}->{alice_id}".encode("utf-8")
    hkdf_ba = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info_ba
    )
    k_ba = hkdf_ba.derive(shared_secret)

    return k_ab, k_ba


class MessagingHandshake:
    """Manages ephemeral ML-KEM-768 session establishment with long-term identity binding."""

    def __init__(self) -> None:
        self.pqc_kem = MLKEM768()

    def generate_responder_offer(self, responder_id: str, responder_device: str,
                                 signing_key: bytes | ed25519.Ed25519PrivateKey) -> dict[str, Any]:
        """Responder (Bob) creates a fresh ephemeral ML-KEM-768 keypair and signed offer."""
        kem_pk, kem_sk = self.pqc_kem.generate_keypair()
        session_id = f"sess-{secrets.token_hex(16)}"
        now_iso = datetime.now(timezone.utc).isoformat()

        canonical_context = f"quantumvault:offer:v1|{session_id}|{responder_id}|{responder_device}|{kem_pk.hex()}|{now_iso}".encode("utf-8")
        sig_b64 = sign_context(signing_key, canonical_context)

        return {
            "session_id": session_id,
            "responder_id": responder_id,
            "responder_device": responder_device,
            "ephemeral_kem_pk_b64": base64.b64encode(kem_pk).decode("utf-8"),
            "timestamp": now_iso,
            "signature_b64": sig_b64,
            "_ephemeral_sk_bytes": bytearray(kem_sk)  # Keep in volatile memory until decapsulation
        }

    def initiate_session(self, initiator_id: str, initiator_device: str,
                         initiator_signing_key: bytes | ed25519.Ed25519PrivateKey,
                         offer: dict[str, Any],
                         responder_pubkey_b64: str) -> Tuple[dict[str, Any], bytes, bytes]:
        """Initiator (Alice) validates Bob's offer, encapsulates shared secret,
        signs handshake payload, and derives session keys (k_send, k_recv).
        """
        # 1. Verify Bob's offer signature
        session_id = offer["session_id"]
        resp_id = offer["responder_id"]
        resp_device = offer["responder_device"]
        try:
            kem_pk_bytes = base64.b64decode(offer["ephemeral_kem_pk_b64"].strip(), validate=True)
        except Exception as e:
            raise CryptoError(f"Malformed Base64 ephemeral KEM public key in offer: {e}") from e
        offer_ts = offer["timestamp"]

        offer_context = f"quantumvault:offer:v1|{session_id}|{resp_id}|{resp_device}|{kem_pk_bytes.hex()}|{offer_ts}".encode("utf-8")
        if not verify_peer_signature(responder_pubkey_b64, offer_context, offer["signature_b64"]):
            raise SecurityPolicyError("Responder offer signature verification failed; possible MITM")

        # 2. Encapsulate shared secret against Bob's ephemeral KEM public key
        ciphertext, shared_secret = self.pqc_kem.encapsulate(kem_pk_bytes)

        # 3. Sign initiator response
        now_iso = datetime.now(timezone.utc).isoformat()
        init_context = f"quantumvault:init:v1|{session_id}|{initiator_id}|{resp_id}|{initiator_device}|{resp_device}|{ciphertext.hex()}|{now_iso}".encode("utf-8")
        init_sig_b64 = sign_context(initiator_signing_key, init_context)

        # 4. Derive symmetric session keys
        k_init_send, k_init_recv = derive_session_keys(
            shared_secret=shared_secret,
            session_id=session_id,
            alice_id=initiator_id,
            bob_id=resp_id
        )

        handshake_payload = {
            "session_id": session_id,
            "initiator_id": initiator_id,
            "initiator_device": initiator_device,
            "responder_id": resp_id,
            "responder_device": resp_device,
            "kem_ciphertext_b64": base64.b64encode(ciphertext).decode("utf-8"),
            "timestamp": now_iso,
            "signature_b64": init_sig_b64
        }

        # Best-effort cleanup (CPython immutable bytes references are dropped, not overwritten in-place)
        del shared_secret

        return handshake_payload, k_init_send, k_init_recv

    def complete_responder(self, offer: dict[str, Any],
                           initiator_payload: dict[str, Any],
                           initiator_pubkey_b64: str) -> Tuple[bytes, bytes]:
        """Responder (Bob) verifies Alice's signature, decapsulates shared secret,
        derives session keys (k_recv, k_send), and zeroizes the mutable ephemeral secret key buffer.
        """
        session_id = initiator_payload["session_id"]
        init_id = initiator_payload["initiator_id"]
        init_dev = initiator_payload["initiator_device"]
        resp_id = initiator_payload["responder_id"]
        resp_dev = initiator_payload["responder_device"]

        if session_id != offer.get("session_id") or resp_id != offer.get("responder_id") or resp_dev != offer.get("responder_device"):
            raise SecurityPolicyError("Handshake context mismatch between responder offer and initiator response")

        try:
            ct_bytes = base64.b64decode(initiator_payload["kem_ciphertext_b64"].strip(), validate=True)
        except Exception as e:
            raise CryptoError(f"Malformed Base64 KEM ciphertext: {e}") from e
        ts = initiator_payload["timestamp"]

        # Verify Alice's identity signature
        init_context = f"quantumvault:init:v1|{session_id}|{init_id}|{resp_id}|{init_dev}|{resp_dev}|{ct_bytes.hex()}|{ts}".encode("utf-8")
        if not verify_peer_signature(initiator_pubkey_b64, init_context, initiator_payload["signature_b64"]):
            raise SecurityPolicyError("Initiator signature verification failed; untrusted peer")

        # Decapsulate shared secret using ephemeral secret key
        sk_bytes = offer.get("_ephemeral_sk_bytes")
        if not sk_bytes:
            raise CryptoError("Ephemeral secret key already destroyed or unavailable")

        try:
            shared_secret = self.pqc_kem.decapsulate(bytes(sk_bytes), ct_bytes)
        finally:
            # Ephemeral Secret Key Erasure (mutable bytearray overwritten in-place)
            zeroize_bytes(sk_bytes)
            offer["_ephemeral_sk_bytes"] = None

        # Derive symmetric session keys
        k_init_send, k_init_recv = derive_session_keys(
            shared_secret=shared_secret,
            session_id=session_id,
            alice_id=init_id,
            bob_id=resp_id
        )

        del shared_secret

        # Return (k_bob_recv, k_bob_send)
        return k_init_send, k_init_recv
