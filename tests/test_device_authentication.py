"""Tests for device registration, challenge-response authentication, and proof-of-possession (DEV01 - DEV12)."""
import base64
from pathlib import Path
import tempfile
import time
import unittest

from quantumvault.core.errors import AuthenticationError, AuthorizationError, IdentityError
from quantumvault.iam.authentication import (
    DeviceAuthenticator,
    generate_device_keypair,
    sign_challenge,
)
from quantumvault.iam.device import DeviceManager
from quantumvault.iam.recovery import RecoveryManager
from quantumvault.storage.db import get_connection, init_db, transaction
from quantumvault.storage.repositories import IdentityRepository


class TestDeviceAuthentication(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.conn = get_connection(self.db_path)
        init_db(self.conn)

        self.identities = IdentityRepository(self.conn)
        self.device_mgr = DeviceManager(self.conn)
        self.auth = DeviceAuthenticator(self.conn, ttl_seconds=2.0)
        self.recovery = RecoveryManager(self.conn)

        # Create base active identity
        with transaction(self.conn):
            self.identities.upsert("alice", status="active", role="viewer")
            self.identities.upsert("bob", status="disabled", role="viewer")

    def tearDown(self):
        self.conn.close()
        self.temp_dir.cleanup()

    def test_dev01_valid_device_enrollment(self):
        """DEV01: Valid device enrollment binds to active actor."""
        priv, pub_b64 = generate_device_keypair()
        res = self.device_mgr.enroll_device("alice", "dev-alice-phone", pub_b64)
        self.assertEqual(res["device_id"], "dev-alice-phone")
        self.assertEqual(res["status"], "active")
        self.assertTrue(self.device_mgr.is_device_active("dev-alice-phone"))

    def test_dev02_enroll_unknown_actor_fails(self):
        """DEV02: Cannot enroll device for non-existent actor."""
        _, pub_b64 = generate_device_keypair()
        with self.assertRaises(AuthorizationError):
            self.device_mgr.enroll_device("unknown-actor", "dev-ghost", pub_b64)

    def test_dev03_enroll_disabled_actor_fails(self):
        """DEV03: Cannot enroll device for disabled/revoked actor."""
        _, pub_b64 = generate_device_keypair()
        with self.assertRaises(AuthorizationError):
            self.device_mgr.enroll_device("bob", "dev-bob-laptop", pub_b64)

    def test_dev04_malformed_public_key_rejected(self):
        """DEV04: Malformed or wrong-length Base64 public key is rejected."""
        with self.assertRaises(IdentityError):
            self.device_mgr.enroll_device("alice", "dev-bad-1", "not-base-64!!!")
        with self.assertRaises(IdentityError):
            short_b64 = base64.b64encode(b"short-key").decode("ascii")
            self.device_mgr.enroll_device("alice", "dev-bad-2", short_b64)

    def test_dev05_challenge_generation_has_ttl(self):
        """DEV05: Challenge generation produces 64-char hex token with TTL."""
        _, pub_b64 = generate_device_keypair()
        self.device_mgr.enroll_device("alice", "dev-alice-1", pub_b64)

        challenge_data = self.auth.create_challenge("dev-alice-1")
        token = challenge_data["challenge"]
        self.assertEqual(len(token), 64)
        self.assertEqual(challenge_data["device_id"], "dev-alice-1")
        self.assertGreater(challenge_data["expires_in"], 0)

    def test_dev06_valid_signature_authenticates(self):
        """DEV06: Valid Ed25519 signature over challenge authenticates successfully."""
        priv, pub_b64 = generate_device_keypair()
        self.device_mgr.enroll_device("alice", "dev-alice-valid", pub_b64)

        chal = self.auth.create_challenge("dev-alice-valid")["challenge"]
        sig_b64 = sign_challenge(priv, chal)

        authenticated = self.auth.verify_response("dev-alice-valid", chal, sig_b64)
        self.assertTrue(authenticated)

    def test_dev07_corrupted_signature_fails(self):
        """DEV07: Invalid or altered signature fails verification."""
        priv, pub_b64 = generate_device_keypair()
        self.device_mgr.enroll_device("alice", "dev-alice-corrupt", pub_b64)

        chal = self.auth.create_challenge("dev-alice-corrupt")["challenge"]
        sig_b64 = sign_challenge(priv, chal)

        # Alter single character in signature
        corrupted = ("A" if sig_b64[0] != "A" else "B") + sig_b64[1:]
        authenticated = self.auth.verify_response("dev-alice-corrupt", chal, corrupted)
        self.assertFalse(authenticated)

    def test_dev08_wrong_device_id_fails(self):
        """DEV08: Presenting challenge against wrong device ID fails authentication."""
        priv1, pub_b64_1 = generate_device_keypair()
        _, pub_b64_2 = generate_device_keypair()
        self.device_mgr.enroll_device("alice", "dev-1", pub_b64_1)
        self.device_mgr.enroll_device("alice", "dev-2", pub_b64_2)

        chal = self.auth.create_challenge("dev-1")["challenge"]
        sig_b64 = sign_challenge(priv1, chal)

        # Attempt to claim challenge belongs to dev-2
        authenticated = self.auth.verify_response("dev-2", chal, sig_b64)
        self.assertFalse(authenticated)

    def test_dev09_single_use_challenge_prevents_replay(self):
        """DEV09: Challenge is consumed immediately; replay fails on second attempt."""
        priv, pub_b64 = generate_device_keypair()
        self.device_mgr.enroll_device("alice", "dev-replay", pub_b64)

        chal = self.auth.create_challenge("dev-replay")["challenge"]
        sig_b64 = sign_challenge(priv, chal)

        # First verification succeeds
        self.assertTrue(self.auth.verify_response("dev-replay", chal, sig_b64))
        # Second verification with exact same challenge and signature fails
        self.assertFalse(self.auth.verify_response("dev-replay", chal, sig_b64))

    def test_dev10_expired_challenge_fails(self):
        """DEV10: Verification of an expired challenge fails."""
        # Use very short TTL of 0.1s
        short_auth = DeviceAuthenticator(self.conn, ttl_seconds=0.1)
        priv, pub_b64 = generate_device_keypair()
        self.device_mgr.enroll_device("alice", "dev-expire", pub_b64)

        chal = short_auth.create_challenge("dev-expire")["challenge"]
        sig_b64 = sign_challenge(priv, chal)

        time.sleep(0.15)  # Wait for expiration
        self.assertFalse(short_auth.verify_response("dev-expire", chal, sig_b64))

    def test_dev11_multi_device_registration(self):
        """DEV11: Single actor can enroll multiple independent devices."""
        _, pub1 = generate_device_keypair()
        _, pub2 = generate_device_keypair()
        self.device_mgr.enroll_device("alice", "dev-phone", pub1)
        self.device_mgr.enroll_device("alice", "dev-laptop", pub2)

        devices = self.device_mgr.list_actor_devices("alice")
        dev_ids = {d["device_id"] for d in devices}
        self.assertEqual(dev_ids, {"dev-phone", "dev-laptop"})

    def test_dev12_individual_device_revocation_isolation(self):
        """DEV12: Revoking phone leaves laptop active for the same actor."""
        _, pub1 = generate_device_keypair()
        _, pub2 = generate_device_keypair()
        self.device_mgr.enroll_device("alice", "dev-phone", pub1)
        self.device_mgr.enroll_device("alice", "dev-laptop", pub2)

        self.device_mgr.revoke_device("dev-phone")
        self.assertFalse(self.device_mgr.is_device_active("dev-phone"))
        self.assertTrue(self.device_mgr.is_device_active("dev-laptop"))


if __name__ == "__main__":
    unittest.main()
