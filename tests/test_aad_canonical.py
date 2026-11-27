"""Tests for canonical length-prefixed Associated Authenticated Data (AAD) framing.
Verifies boundary-shifting protection, unicode handling, cross-owner substitution rejection,
and transparent backward-compatibility migration.
"""
import unittest

from quantumvault.core.errors import CryptoError
from quantumvault.crypto.aad import (
    construct_key_version_aad,
    construct_legacy_key_version_aad,
    construct_legacy_outbox_aad,
    construct_legacy_resource_aad,
    construct_message_aad_canonical,
    construct_outbox_aad,
    construct_resource_aad,
    encode_length_prefixed,
)
from quantumvault.crypto.encryption import AuthenticatedEncryption
from quantumvault.messaging.e2ee import MessageCipher, construct_legacy_message_aad


class TestCanonicalAAD(unittest.TestCase):
    def test_aad01_boundary_shifting_collision_resistance(self):
        # In a naive colon-separated scheme: "a:b" + ":" + "c" == "a" + ":" + "b:c" == "a:b:c"
        # In our length-prefixed canonical encoding, they MUST produce distinct byte sequences.
        tag = b"TEST_TAG\x00"
        enc1 = encode_length_prefixed(["a:b", "c"], tag)
        enc2 = encode_length_prefixed(["a", "b:c"], tag)
        self.assertNotEqual(enc1, enc2)

        # Pipe delimiter test
        enc3 = encode_length_prefixed(["x|y", "z"], tag)
        enc4 = encode_length_prefixed(["x", "y|z"], tag)
        self.assertNotEqual(enc3, enc4)

    def test_aad02_unicode_and_empty_fields(self):
        tag = b"QV_ASSET_v2\x00"
        # Empty fields
        enc_empty = encode_length_prefixed(["", ""], tag)
        self.assertTrue(enc_empty.startswith(tag))
        # Unicode characters with multi-byte UTF-8 representations
        enc_unicode = encode_length_prefixed(["ಕನ್ನಡ_ರಹಸ್ಯ", "用户_123_🔐"], tag)
        self.assertTrue(len(enc_unicode) > len(tag))

    def test_aad03_resource_aad_uniqueness(self):
        aad_user1_assetA = construct_resource_aad("assetA", "user1")
        aad_user1_assetB = construct_resource_aad("assetB", "user1")
        aad_user2_assetA = construct_resource_aad("assetA", "user2")
        self.assertNotEqual(aad_user1_assetA, aad_user1_assetB)
        self.assertNotEqual(aad_user1_assetA, aad_user2_assetA)

    def test_aad04_authenticated_encryption_cross_owner_substitution(self):
        key = b"K" * 32
        cipher = AuthenticatedEncryption(key)

        # Encrypt with owner1 AAD
        aad1 = construct_resource_aad("asset_alpha", "owner_alice")
        ct, nonce = cipher.encrypt("secret_payload", associated_data=aad1)

        # Decrypt with correct AAD succeeds
        pt = cipher.decrypt(ct, nonce, associated_data=aad1)
        self.assertEqual(pt, "secret_payload")

        # Decrypt with substituted owner AAD fails
        aad2 = construct_resource_aad("asset_alpha", "owner_bob")
        with self.assertRaises(CryptoError):
            cipher.decrypt(ct, nonce, associated_data=aad2)

        # Decrypt with substituted asset AAD fails
        aad3 = construct_resource_aad("asset_beta", "owner_alice")
        with self.assertRaises(CryptoError):
            cipher.decrypt(ct, nonce, associated_data=aad3)

    def test_aad05_legacy_migration_resource_aad(self):
        key = b"K" * 32
        cipher = AuthenticatedEncryption(key)

        # Legacy encryption (colon delimited)
        legacy_aad = construct_legacy_resource_aad("legacy_asset", "user_1")
        ct, nonce = cipher.encrypt("legacy_content", associated_data=legacy_aad)

        # Test dual decrypt pattern used in resources.py
        canonical_aad = construct_resource_aad("legacy_asset", "user_1")
        try:
            pt = cipher.decrypt(ct, nonce, associated_data=canonical_aad)
        except CryptoError:
            pt = cipher.decrypt(ct, nonce, associated_data=legacy_aad)
        self.assertEqual(pt, "legacy_content")

    def test_aad06_e2ee_message_cipher_canonical_and_legacy(self):
        key = b"M" * 32
        sender_cipher = MessageCipher(
            key=key,
            session_id="sess-xyz",
            sender_id="alice",
            sender_device="dev-a",
            recipient_id="bob",
            recipient_device="dev-b"
        )
        receiver_cipher = MessageCipher(
            key=key,
            session_id="sess-xyz",
            sender_id="bob",
            sender_device="dev-b",
            recipient_id="alice",
            recipient_device="dev-a"
        )

        # Encrypt using canonical AAD
        envelope = sender_cipher.encrypt_message("Canonical E2EE payload", sequence_num=42)
        decrypted = receiver_cipher.decrypt_message(envelope)
        self.assertEqual(decrypted.decode("utf-8"), "Canonical E2EE payload")

        # Receiver should reject when recipient is tampered in envelope
        tampered_env = dict(envelope)
        tampered_env["recipient_id"] = "mallory"
        with self.assertRaises(CryptoError):
            receiver_cipher.decrypt_message(tampered_env)


if __name__ == "__main__":
    unittest.main()
