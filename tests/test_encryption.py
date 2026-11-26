"""Tests for authenticated resource vault encryption and AES-256-GCM (EN01 - EN07)."""
from pathlib import Path
import sqlite3
import tempfile
import unittest

from quantumvault.core.errors import CryptoError
from quantumvault.crypto.encryption import AuthenticatedEncryption
from quantumvault.storage.db import get_connection, init_db
from quantumvault.vault.resources import ResourceVault


class TestEncryption(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "vault.db"
        self.conn = get_connection(self.db_path)
        init_db(self.conn)

        self.key = b"\x01" * 32  # 256-bit test key
        self.cipher = AuthenticatedEncryption(self.key)
        self.vault = ResourceVault(self.conn, self.cipher)

    def tearDown(self):
        self.conn.close()
        self.temp_dir.cleanup()

    def test_en01_encrypt_and_decrypt_roundtrip(self):
        """EN01: Plaintext encrypts and decrypts to exact original string."""
        plaintext = "High-security secret payload 🔒"
        ct, nonce = self.cipher.encrypt(plaintext)
        recovered = self.cipher.decrypt(ct, nonce)
        self.assertEqual(plaintext, recovered)

    def test_en02_content_not_stored_as_plaintext(self):
        """EN02: Stored asset in SQLite database is ciphertext, not plaintext."""
        secret = "UltraConfidentialText12345"
        self.conn.execute("INSERT INTO identities (actor_id, status) VALUES ('owner-x', 'active');")
        self.vault.store_resource("asset-x", "owner-x", secret)

        cursor = self.conn.execute("SELECT encrypted_body FROM assets WHERE asset_id = 'asset-x';")
        row = cursor.fetchone()
        raw_blob = bytes(row["encrypted_body"])
        
        # Assert raw plaintext string is nowhere in the stored database blob
        self.assertNotIn(secret.encode("utf-8"), raw_blob)

    def test_en03_modified_ciphertext_fails_authentication(self):
        """EN03: Altering a single bit in ciphertext triggers authentication failure."""
        plaintext = "Sensitive data"
        ct, nonce = self.cipher.encrypt(plaintext)
        
        # Tamper with one byte in ciphertext
        tampered_ct = bytearray(ct)
        tampered_ct[0] ^= 0xFF
        
        with self.assertRaises(CryptoError):
            self.cipher.decrypt(bytes(tampered_ct), nonce)

    def test_en04_incorrect_key_fails_authentication(self):
        """EN04: Decryption using wrong 256-bit key fails authentication."""
        plaintext = "Protected information"
        ct, nonce = self.cipher.encrypt(plaintext)
        
        wrong_cipher = AuthenticatedEncryption(b"\x02" * 32)
        with self.assertRaises(CryptoError):
            wrong_cipher.decrypt(ct, nonce)

    def test_en05_nonce_uniqueness(self):
        """EN05: Each encryption operation uses a distinct 96-bit CSPRNG nonce."""
        nonces = set()
        for _ in range(500):
            _, nonce = self.cipher.encrypt("constant text")
            self.assertNotIn(nonce, nonces)
            nonces.add(nonce)

    def test_en06_associated_data_swapping_fails(self):
        """EN06: AAD binds asset ID and owner; swapping assets fails authentication."""
        self.conn.execute("INSERT INTO identities (actor_id, status) VALUES ('user-1', 'active');")
        self.conn.execute("INSERT INTO identities (actor_id, status) VALUES ('user-2', 'active');")
        self.vault.store_resource("doc-a", "user-1", "Secret A")
        self.vault.store_resource("doc-b", "user-2", "Secret B")

        # Swap the encrypted body of doc-a into doc-b
        cursor = self.conn.execute("SELECT encrypted_body, nonce FROM assets WHERE asset_id = 'doc-a';")
        row_a = cursor.fetchone()

        self.conn.execute(
            "UPDATE assets SET encrypted_body = ?, nonce = ? WHERE asset_id = 'doc-b';",
            (row_a["encrypted_body"], row_a["nonce"])
        )

        # Attempting to retrieve doc-b must fail authentication due to AAD mismatch
        with self.assertRaises(CryptoError):
            self.vault.retrieve_resource("doc-b")


if __name__ == "__main__":
    unittest.main()
