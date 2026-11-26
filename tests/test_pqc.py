"""Tests for ML-KEM-768 post-quantum cryptographic primitives (CR01 - CR10)."""
import base64
import unittest

from quantumvault.core.errors import CryptoError
from quantumvault.crypto.pqc_kem import (
    CIPHERTEXT_SIZE,
    PUBLIC_KEY_SIZE,
    SECRET_KEY_SIZE,
    SHARED_SECRET_SIZE,
    MLKEM768,
)


class TestPQCKEM(unittest.TestCase):
    def setUp(self):
        self.pqc = MLKEM768()

    def test_cr01_genuine_key_generation(self):
        """CR01: Generate genuine ML-KEM-768 keypair matching NIST FIPS 203 sizes."""
        pk, sk = self.pqc.generate_keypair()
        self.assertIsInstance(pk, bytes)
        self.assertIsInstance(sk, bytes)
        self.assertEqual(len(pk), PUBLIC_KEY_SIZE)  # 1184 bytes
        self.assertEqual(len(sk), SECRET_KEY_SIZE)  # 2400 bytes

    def test_cr02_encapsulation_and_decapsulation(self):
        """CR02: Encapsulation creates valid ciphertext and shared secret."""
        pk, sk = self.pqc.generate_keypair()
        ct, ss_sender = self.pqc.encapsulate(pk)
        self.assertEqual(len(ct), CIPHERTEXT_SIZE)        # 1088 bytes
        self.assertEqual(len(ss_sender), SHARED_SECRET_SIZE)  # 32 bytes

        # Decapsulation recovers identical secret
        ss_receiver = self.pqc.decapsulate(sk, ct)
        self.assertEqual(len(ss_receiver), SHARED_SECRET_SIZE)
        self.assertEqual(ss_sender, ss_receiver)

    def test_cr03_multiple_independent_key_agreements(self):
        """CR03: Multiple independent encapsulations yield distinct ciphertexts & secrets."""
        pk, sk = self.pqc.generate_keypair()
        ct1, ss1 = self.pqc.encapsulate(pk)
        ct2, ss2 = self.pqc.encapsulate(pk)
        self.assertNotEqual(ct1, ct2)
        self.assertNotEqual(ss1, ss2)
        self.assertEqual(self.pqc.decapsulate(sk, ct1), ss1)
        self.assertEqual(self.pqc.decapsulate(sk, ct2), ss2)

    def test_cr05_invalid_public_key_length_rejected(self):
        """CR05: Encapsulation with invalid public key length raises CryptoError."""
        with self.assertRaises(CryptoError):
            self.pqc.encapsulate(b"too-short-public-key")

    def test_cr06_malformed_base64_rejected(self):
        """CR06: Invalid Base64 strings raise CryptoError during decoding."""
        with self.assertRaises(CryptoError):
            self.pqc.decode_public_key("not-valid-base64!@#$%")

    def test_cr07_wrong_private_key_fails_agreement(self):
        """CR07: Decapsulation with wrong private key does not recover original secret."""
        pk1, sk1 = self.pqc.generate_keypair()
        _, sk2 = self.pqc.generate_keypair()
        ct, ss1 = self.pqc.encapsulate(pk1)
        
        # In ML-KEM, implicit rejection returns an internal pseudorandom value, not ss1
        ss_wrong = self.pqc.decapsulate(sk2, ct)
        self.assertNotEqual(ss1, ss_wrong)

    def test_cr10_base64_encoding_roundtrip(self):
        """CR10: Public key and ciphertext Base64 conversions preserve byte fidelity."""
        pk, _ = self.pqc.generate_keypair()
        b64 = base64.b64encode(pk).decode("ascii")
        decoded = self.pqc.decode_public_key(b64)
        self.assertEqual(pk, decoded)


if __name__ == "__main__":
    unittest.main()
