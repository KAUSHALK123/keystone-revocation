"""Independent post-quantum cryptographic interoperability verification client (Section 20)."""
import base64
from pathlib import Path
import secrets
import tempfile
import unittest

from quantumvault.core.service import QuantumVaultService
from quantumvault.crypto.hmac_proof import generate_proof, verify_proof
from quantumvault.crypto.pqc_kem import MLKEM768


class TestProtectedReadInteroperability(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp_dir.name)
        self.service = QuantumVaultService(state_dir=self.state_dir)
        self.pqc = MLKEM768()

        self.test_body = "QuantumVault Post-Quantum Confidential Document (FIPS 203 Verified) 🚀"
        self.service.setup(
            owners={"pqc-asset-01": "researcher-alice", "pqc-asset-02": "researcher-bob"},
            contents={"pqc-asset-01": self.test_body, "pqc-asset-02": "Bob's Public Telemetry"},
            disabled=["revoked-user"],
            key_material="master-pqc-synthetic-seed-98765"
        )

    def tearDown(self):
        self.service.close()
        self.temp_dir.cleanup()

    def test_cr04_genuine_pqc_roundtrip_verification(self):
        """CR04: Independent client verifies genuine ML-KEM-768 ciphertext and HMAC proof."""
        # 1. Independent client generates ML-KEM-768 keypair
        client_pk, client_sk = self.pqc.generate_keypair()
        b64_client_pk = base64.b64encode(client_pk).decode("ascii")

        challenge = f"ch-{secrets.token_hex(16)}"

        # 2. Invoke protected_read
        res = self.service.protected_read(
            actor="researcher-alice",
            asset="pqc-asset-01",
            challenge=challenge,
            public_key=b64_client_pk
        )

        self.assertIn("ciphertext", res)
        self.assertIn("proof", res)
        self.assertNotIn("decision", res)

        # 3. Client decodes returned ciphertext
        ct_bytes = base64.b64decode(res["ciphertext"])
        self.assertEqual(len(ct_bytes), 1088)

        # 4. Client decapsulates using independent private key
        recovered_secret = self.pqc.decapsulate(client_sk, ct_bytes)
        self.assertEqual(len(recovered_secret), 32)

        # 5. Client verifies HMAC-SHA-256 proof over (challenge + stored_body)
        is_valid = verify_proof(
            proof=res["proof"],
            shared_secret=recovered_secret,
            challenge=challenge,
            stored_body=self.test_body
        )
        self.assertTrue(is_valid, "Independent client HMAC-SHA-256 proof verification failed!")

    def test_multiple_randomized_pqc_exchanges(self):
        """Verify 5 independent random exchanges with varying keys, bodies, and nonces."""
        for i in range(5):
            body = f"Dynamic payload sequence #{i}: {secrets.token_hex(32)}"
            asset_id = f"asset-{i}"
            actor_id = f"actor-{i}"

            self.service.setup(
                owners={asset_id: actor_id},
                contents={asset_id: body},
                disabled=[],
                key_material=secrets.token_hex(16)
            )

            client_pk, client_sk = self.pqc.generate_keypair()
            b64_pk = base64.b64encode(client_pk).decode("ascii")
            challenge = f"nonce-{i}-{secrets.token_hex(12)}"

            res = self.service.protected_read(
                actor=actor_id,
                asset=asset_id,
                challenge=challenge,
                public_key=b64_pk
            )

            ct_bytes = base64.b64decode(res["ciphertext"])
            ss = self.pqc.decapsulate(client_sk, ct_bytes)
            self.assertTrue(verify_proof(res["proof"], ss, challenge, body))

    def test_cr08_revoked_actor_denied_protected_read(self):
        """CR08: Revoked actor receives deny with no ciphertext or proof."""
        self.service.revoke("researcher-alice")
        client_pk, _ = self.pqc.generate_keypair()
        res = self.service.protected_read(
            actor="researcher-alice",
            asset="pqc-asset-01",
            challenge="ch-1",
            public_key=base64.b64encode(client_pk).decode("ascii")
        )
        self.assertEqual(res, {"decision": "deny"})

    def test_cr09_unauthorized_actor_denied_protected_read(self):
        """CR09: Wrong owner receives deny with no ciphertext or proof."""
        client_pk, _ = self.pqc.generate_keypair()
        res = self.service.protected_read(
            actor="researcher-bob",  # Bob does not own pqc-asset-01
            asset="pqc-asset-01",
            challenge="ch-2",
            public_key=base64.b64encode(client_pk).decode("ascii")
        )
        self.assertEqual(res, {"decision": "deny"})

    def test_malformed_public_key_denied_cleanly(self):
        """Malformed public key returns deny without unhandled exception."""
        res = self.service.protected_read(
            actor="researcher-alice",
            asset="pqc-asset-01",
            challenge="ch-3",
            public_key="not-a-valid-b64-key"
        )
        self.assertEqual(res, {"decision": "deny"})


if __name__ == "__main__":
    unittest.main()
