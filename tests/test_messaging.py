"""Unit tests for Post-Quantum Forward-Secure Authenticated Messaging Subsystem."""
import base64
import sqlite3
import tempfile
import unittest
from pathlib import Path

from quantumvault.core.errors import (
    AuthorizationError,
    CryptoError,
    SecurityPolicyError,
)
from quantumvault.crypto.pqc_dsa import MLDSA65
from quantumvault.iam.authentication import generate_device_keypair
from quantumvault.messaging.e2ee import MessageCipher
from quantumvault.messaging.forward_secrecy import ForwardSecrecyHarness
from quantumvault.messaging.handshake import MessagingHandshake
from quantumvault.messaging.outbox import EncryptedOutbox
from quantumvault.messaging.replay import ReplayProtector
from quantumvault.messaging.session import MessagingSession
from quantumvault.messaging.transport import ChunkedTransport
from quantumvault.storage.db import get_connection


class TestMessagingHandshake(unittest.TestCase):
    def setUp(self):
        self.hs = MessagingHandshake()
        self.sk_alice, self.pk_alice = generate_device_keypair()
        self.sk_bob, self.pk_bob = generate_device_keypair()

    def test_msg01_successful_handshake(self):
        offer = self.hs.generate_responder_offer("bob", "dev-b", self.sk_bob)
        self.assertIn("session_id", offer)
        self.assertIn("ephemeral_kem_pk_b64", offer)

        init_payload, k_a_send, k_a_recv = self.hs.initiate_session(
            "alice", "dev-a", self.sk_alice, offer, self.pk_bob
        )
        self.assertEqual(len(k_a_send), 32)
        self.assertEqual(len(k_a_recv), 32)

        k_b_recv, k_b_send = self.hs.complete_responder(offer, init_payload, self.pk_alice)
        self.assertEqual(k_a_send, k_b_recv)
        self.assertEqual(k_a_recv, k_b_send)
        self.assertIsNone(offer["_ephemeral_sk_bytes"])  # Forward secrecy erasure!

    def test_msg02_tampered_offer_signature_rejected(self):
        offer = self.hs.generate_responder_offer("bob", "dev-b", self.sk_bob)
        offer["signature_b64"] = base64.b64encode(b"invalid-sig" * 4).decode("utf-8")
        with self.assertRaises(SecurityPolicyError):
            self.hs.initiate_session("alice", "dev-a", self.sk_alice, offer, self.pk_bob)

    def test_msg03_tampered_initiator_signature_rejected(self):
        offer = self.hs.generate_responder_offer("bob", "dev-b", self.sk_bob)
        init_payload, _, _ = self.hs.initiate_session("alice", "dev-a", self.sk_alice, offer, self.pk_bob)
        init_payload["signature_b64"] = base64.b64encode(b"fake-sig" * 4).decode("utf-8")
        with self.assertRaises(SecurityPolicyError):
            self.hs.complete_responder(offer, init_payload, self.pk_alice)

    def test_msg04_pqc_mldsa65_handshake(self):
        dsa = MLDSA65()
        pk_a, sk_a = dsa.generate_keypair()
        pk_b, sk_b = dsa.generate_keypair()
        pk_a_b64 = dsa.encode_public_key(pk_a)
        pk_b_b64 = dsa.encode_public_key(pk_b)

        offer = self.hs.generate_responder_offer("bob-pqc", "dev-bpqc", sk_b)
        init_payload, k_a_send, k_a_recv = self.hs.initiate_session(
            "alice-pqc", "dev-apqc", sk_a, offer, pk_b_b64
        )
        k_b_recv, k_b_send = self.hs.complete_responder(offer, init_payload, pk_a_b64)
        self.assertEqual(k_a_send, k_b_recv)
        self.assertEqual(k_a_recv, k_b_send)


class TestMessageEncryptionAndSession(unittest.TestCase):
    def setUp(self):
        self.key = b"A" * 32
        self.cipher = MessageCipher(
            key=self.key,
            session_id="sess-test-1",
            sender_id="alice",
            sender_device="dev-a",
            recipient_id="bob",
            recipient_device="dev-b"
        )

    def test_enc01_encrypt_decrypt_roundtrip(self):
        plaintext = "Post-Quantum Confidential Message 2026"
        env = self.cipher.encrypt_message(plaintext, sequence_num=1)
        self.assertEqual(env["sequence_num"], 1)

        recv_cipher = MessageCipher(
            key=self.key,
            session_id="sess-test-1",
            sender_id="bob",
            sender_device="dev-b",
            recipient_id="alice",
            recipient_device="dev-a"
        )
        decrypted = self.cipher.decrypt_message(env)
        self.assertEqual(decrypted.decode("utf-8"), plaintext)

    def test_enc02_tampered_ciphertext_rejected(self):
        env = self.cipher.encrypt_message("Authentic Message", sequence_num=1)
        ct = bytearray(base64.b64decode(env["ciphertext_b64"]))
        ct[0] ^= 0x01
        env["ciphertext_b64"] = base64.b64encode(ct).decode("utf-8")
        with self.assertRaises(CryptoError):
            self.cipher.decrypt_message(env)

    def test_enc03_tampered_recipient_binding_rejected(self):
        env = self.cipher.encrypt_message("Authentic Message", sequence_num=1)
        env["recipient_id"] = "eve"  # Modifying AAD!
        with self.assertRaises(CryptoError):
            self.cipher.decrypt_message(env)

    def test_ses01_bi_directional_session(self):
        k_ab = b"1" * 32
        k_ba = b"2" * 32
        alice_sess = MessagingSession("s-01", "alice", "dev-a", "bob", "dev-b", k_ab, k_ba)
        bob_sess = MessagingSession("s-01", "bob", "dev-b", "alice", "dev-a", k_ba, k_ab)

        # Alice -> Bob
        m1 = alice_sess.send_message("Hello from Alice")
        dec1 = bob_sess.receive_message(m1)
        self.assertEqual(dec1.decode("utf-8"), "Hello from Alice")

        # Bob -> Alice
        m2 = bob_sess.send_message("Hello back from Bob")
        dec2 = alice_sess.receive_message(m2)
        self.assertEqual(dec2.decode("utf-8"), "Hello back from Bob")

    def test_ses02_resumption_strictly_unsupported(self):
        with self.assertRaises(SecurityPolicyError) as ctx:
            MessagingSession.resume_session("session-ticket-id")
        self.assertIn("explicitly unsupported", str(ctx.exception))


class TestReplayProtection(unittest.TestCase):
    def test_rpl01_sliding_window_duplicate_rejection(self):
        rp = ReplayProtector(window_size=64)
        rp.check_and_record("msg-1", "sess-1", 1)
        with self.assertRaises(SecurityPolicyError):
            rp.check_and_record("msg-1", "sess-1", 1)

    def test_rpl02_out_of_window_rejection(self):
        rp = ReplayProtector(window_size=64)
        rp.check_and_record("msg-100", "sess-1", 100)
        # Sequence 30 is outside window (100 - 30 = 70 >= 64)
        with self.assertRaises(SecurityPolicyError):
            rp.check_and_record("msg-30", "sess-1", 30)

    def test_rpl03_persistent_cache_rejection(self):
        with tempfile.TemporaryDirectory() as td:
            conn = get_connection(Path(td) / "test.db")
            try:
                conn.executescript((Path(__file__).parents[1] / "quantumvault" / "storage" / "schema.sql").read_text(encoding="utf-8"))
                rp = ReplayProtector(conn=conn, window_size=64)
                rp.check_and_record("msg-pers-1", "s1", 1)
                with self.assertRaises(SecurityPolicyError):
                    rp.check_and_record("msg-pers-1", "s1", 1)
            finally:
                conn.close()


class TestTransportAndOutbox(unittest.TestCase):
    def test_net01_chunked_segmentation_reassembly(self):
        transport = ChunkedTransport(chunk_size=50)
        payload = b"QuantumVault" * 20  # 240 bytes -> 5 chunks
        chunks = transport.segment_payload("msg-test", payload)
        self.assertEqual(len(chunks), 5)

        # Reassemble out-of-order
        shuffled = [chunks[3], chunks[0], chunks[4], chunks[1], chunks[2]]
        ok, assembled, missing = transport.reassemble(shuffled)
        self.assertTrue(ok)
        self.assertEqual(assembled, payload)
        self.assertEqual(missing, [])

    def test_net02_chunk_loss_detection(self):
        transport = ChunkedTransport(chunk_size=50)
        payload = b"TestPayload" * 15
        chunks = transport.segment_payload("msg-loss", payload)
        received = [chunks[0], chunks[2]]  # Dropped chunk 1 and 3
        ok, assembled, missing = transport.reassemble(received)
        self.assertFalse(ok)
        self.assertIsNone(assembled)
        self.assertIn(1, missing)
        self.assertIn(3, missing)

    def test_off01_outbox_offline_revocation_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            conn = get_connection(Path(td) / "test.db")
            try:
                conn.executescript((Path(__file__).parents[1] / "quantumvault" / "storage" / "schema.sql").read_text(encoding="utf-8"))
                conn.execute("INSERT INTO identities (actor_id, status, role) VALUES ('alice', 'active', 'viewer');")
                conn.execute("INSERT INTO identities (actor_id, status, role) VALUES ('bob', 'active', 'viewer');")
                outbox = EncryptedOutbox(conn, local_storage_key=b"K" * 32)
                outbox.enqueue("alice", "dev-a", "bob", "Offline message payload")

                # Revoke alice while offline
                conn.execute("INSERT INTO revocations (actor_id, entity_type, reason) VALUES ('alice', 'actor', 'compromised');")
                with self.assertRaises(AuthorizationError):
                    outbox.flush("alice", lambda a, r, p: True)
            finally:
                conn.close()


class TestForwardSecrecy(unittest.TestCase):
    def test_fs01_post_compromise_forward_secrecy(self):
        harness = ForwardSecrecyHarness()
        res = harness.run_compromise_simulation()
        self.assertTrue(res["forward_secrecy_preserved"])
        self.assertTrue(res["ephemeral_key_zeroized"])
        self.assertFalse(res["captured_transcript_decrypted"])


if __name__ == "__main__":
    unittest.main()
