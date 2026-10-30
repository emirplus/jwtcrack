import time
import unittest

from jwtcrack.education import explain_token, list_labs, get_lab, CLAIM_EXPLANATIONS
from jwtcrack.decoder import decode_token
from jwtcrack.forger import generate_token


class TestEducationModule(unittest.TestCase):
    def test_claim_explanations_dictionary(self):
        self.assertIn("sub", CLAIM_EXPLANATIONS)
        self.assertIn("exp", CLAIM_EXPLANATIONS)
        self.assertIn("role", CLAIM_EXPLANATIONS)

    def test_explain_token_hs256_active(self):
        secret = "secret123"
        now = int(time.time())
        token = generate_token(secret, {
            "sub": "user_42",
            "role": "editor",
            "iat": now,
            "exp": now + 3600,
            "custom_flag": True,
        })["token"]

        decoded = decode_token(token)
        explanation = explain_token(decoded)

        self.assertEqual(explanation["algorithm"], "HS256")
        self.assertEqual(explanation["algorithm_type"], "Symmetric (HMAC)")
        self.assertIn("shared secret key", explanation["algorithm_detail"])

        claims = {c["key"]: c for c in explanation["claims"]}
        self.assertIn("sub", claims)
        self.assertEqual(claims["sub"]["value"], "user_42")
        self.assertEqual(claims["sub"]["title"], "Subject")

        self.assertIn("exp", claims)
        self.assertIn("ACTIVE", claims["exp"]["human_readable"])

        self.assertIn("custom_flag", claims)
        self.assertEqual(claims["custom_flag"]["title"], "Custom Claim")

    def test_explain_token_expired(self):
        past = 1500000000
        token = generate_token("secret", {
            "sub": "old_user",
            "exp": past,
        })["token"]
        decoded = decode_token(token)
        explanation = explain_token(decoded)
        claims = {c["key"]: c for c in explanation["claims"]}
        self.assertIn("EXPIRED", claims["exp"]["human_readable"])

    def test_explain_token_asymmetric(self):
        token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.fakeSig"
        decoded = decode_token(token)
        explanation = explain_token(decoded)
        self.assertEqual(explanation["algorithm_type"], "Asymmetric (Public/Private Keypair)")

    def test_explain_token_none_alg(self):
        token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMifQ."
        decoded = decode_token(token)
        explanation = explain_token(decoded)
        self.assertEqual(explanation["algorithm_type"], "Insecure / None")

    def test_list_labs(self):
        labs = list_labs()
        self.assertEqual(len(labs), 5)
        for lab in labs:
            self.assertIn("id", lab)
            self.assertIn("title", lab)
            self.assertIn("difficulty", lab)
            self.assertIn("objective", lab)
            self.assertIn("token", lab)
            self.assertIn("hint", lab)

    def test_get_lab(self):
        lab1 = get_lab(1)
        self.assertEqual(lab1["id"], 1)
        self.assertEqual(lab1["difficulty"], "Beginner")

        with self.assertRaises(ValueError):
            get_lab(999)


if __name__ == "__main__":
    unittest.main()
