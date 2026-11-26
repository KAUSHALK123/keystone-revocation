"""Device authentication, challenge-response protocol, and digital signatures."""
import base64
from datetime import datetime, timezone
import secrets
import sqlite3
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from quantumvault.core.errors import AuthenticationError, CryptoError
from quantumvault.crypto.pqc_dsa import MLDSA65
from quantumvault.iam.device import DeviceManager


def generate_device_keypair() -> tuple[ed25519.Ed25519PrivateKey, str]:
    """Generate an Ed25519 keypair for a device.
    
    Returns:
        (private_key_object, public_key_base64)
    """
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
    return priv, pub_b64


def generate_pqc_device_keypair() -> tuple[bytes, str]:
    """Generate an ML-DSA-65 post-quantum signature keypair for a device.
    
    Returns:
        (secret_key_bytes, public_key_base64)
    """
    dsa = MLDSA65()
    pk, sk = dsa.generate_keypair()
    return sk, dsa.encode_public_key(pk)


def sign_challenge(private_key: ed25519.Ed25519PrivateKey | bytes, challenge_str: str) -> str:
    """Sign a challenge string using the device's private key (Ed25519 or ML-DSA-65).
    
    Returns:
        Base64-encoded signature
    """
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        sig = private_key.sign(challenge_str.encode("utf-8"))
        return base64.b64encode(sig).decode("ascii")
    elif isinstance(private_key, (bytes, bytearray)):
        # ML-DSA-65 private key
        dsa = MLDSA65()
        sig = dsa.sign(bytes(private_key), challenge_str)
        return dsa.encode_signature(sig)
    else:
        raise CryptoError("Unsupported private key type for signing challenge")


class DeviceAuthenticator:
    """Issues CSPRNG challenges and verifies Ed25519 or ML-DSA proof-of-possession signatures."""

    def __init__(self, conn: sqlite3.Connection, ttl_seconds: float = 60.0):
        self.conn = conn
        self.device_mgr = DeviceManager(conn)
        self.ttl_seconds = ttl_seconds
        # In-memory transient challenge cache: challenge_token -> {device_id, actor_id, expires_at, ...}
        self._active_challenges: dict[str, dict[str, Any]] = {}

    def create_challenge(self, device_id: str, purpose: str = "authentication",
                         session_id: str | None = None,
                         credential_version: str = "v1") -> dict[str, Any]:
        """Issue a cryptographically random challenge bound to device, actor, purpose, and version."""
        if not self.device_mgr.is_device_active(device_id):
            raise AuthenticationError(f"Device '{device_id}' is not active or is revoked")

        dev = self.device_mgr.get_device(device_id)
        if not dev:
            raise AuthenticationError(f"Unknown device '{device_id}'")

        actor_id = dev["actor_id"]
        token = secrets.token_hex(32)
        expires_at = time.time() + self.ttl_seconds

        # Cryptographic context binding string
        canonical_context = (
            f"quantumvault:auth:v1|{actor_id}|{device_id}|{purpose}|"
            f"{token}|{session_id or 'none'}|{credential_version}|{expires_at}"
        )

        self._active_challenges[token] = {
            "token": token,
            "device_id": device_id,
            "actor_id": actor_id,
            "purpose": purpose,
            "session_id": session_id,
            "credential_version": credential_version,
            "canonical_context": canonical_context,
            "expires_at": expires_at,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        return {
            "challenge": token,
            "canonical_context": canonical_context,
            "device_id": device_id,
            "actor_id": actor_id,
            "purpose": purpose,
            "expires_in": self.ttl_seconds
        }

    def verify_response(self, device_id: str, challenge: str, signature_b64: str,
                        expected_purpose: str | None = None,
                        expected_actor_id: str | None = None,
                        expected_credential_version: str | None = None) -> bool:
        """Verify the signature over the challenge with strict context binding.
        
        Challenges are single-use: consumed immediately upon verification attempt.
        """
        # Anti-replay: Pop challenge immediately
        entry = self._active_challenges.pop(challenge, None)
        if not entry:
            return False

        if time.time() > entry["expires_at"]:
            return False

        if entry["device_id"] != device_id:
            return False

        # Verify context bindings if caller specified expectations
        if expected_purpose and entry.get("purpose") != expected_purpose:
            return False
        if expected_actor_id and entry.get("actor_id") != expected_actor_id:
            return False
        if expected_credential_version and entry.get("credential_version") != expected_credential_version:
            return False

        if not self.device_mgr.is_device_active(device_id):
            return False

        dev = self.device_mgr.get_device(device_id)
        if not dev:
            return False

        pub_b64 = dev["public_key_b64"]
        canonical_context = entry.get("canonical_context", challenge)

        # Try verification against canonical_context first, then fallback to raw challenge token
        # This supports both context-bound modern signers and simple token signers
        return self._verify_sig_internal(pub_b64, signature_b64, canonical_context) or \
               self._verify_sig_internal(pub_b64, signature_b64, challenge)

    def _verify_sig_internal(self, pub_b64: str, sig_b64: str, payload_str: str) -> bool:
        """Internal signature dispatcher supporting Ed25519 and ML-DSA-65 keys."""
        try:
            pub_bytes = base64.b64decode(pub_b64.strip(), validate=True)
            sig_bytes = base64.b64decode(sig_b64.strip(), validate=True)

            if len(pub_bytes) == 32:
                # Ed25519 public key (32 bytes)
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
                public_key.verify(sig_bytes, payload_str.encode("utf-8"))
                return True
            elif len(pub_bytes) == 1952:
                # ML-DSA-65 public key (1952 bytes)
                dsa = MLDSA65()
                return dsa.verify(pub_bytes, payload_str, sig_bytes)
            else:
                return False
        except (InvalidSignature, ValueError, CryptoError, Exception):
            return False
