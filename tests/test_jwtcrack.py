import unittest
import tempfile
import os
import time

from jwtcrack.decoder import base64url_decode, base64url_encode, split_token, decode_token
from jwtcrack.analyzer import analyze_token, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM
from jwtcrack.cracker import crack_token
from jwtcrack.forger import forge_token, generate_token, forge_none_token, _parse_duration


class TestBase64Url(unittest.TestCase):
    def test_encode_decode_roundtrip(self):
        sample = "hello world! 123 / + = ?"
        encoded = base64url_encode(sample)
        self.assertNotIn("=", encoded)
        self.assertNotIn("+", encoded)
        self.assertNotIn("/", encoded)
        decoded = base64url_decode(encoded).decode("utf-8")
        self.assertEqual(decoded, sample)

    def test_split_token_three_parts(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3j"
        h, p, s = split_token(token)
        self.assertEqual(h, "eyJhbGciOiJIUzI1NiJ9")
        self.assertEqual(p, "eyJzdWIiOiIxMjM0NTY3ODkwIn0")
        self.assertEqual(s, "dozjgNryP4J3j")

    def test_split_token_invalid_parts(self):
        with self.assertRaises(ValueError):
            split_token("onlyonepart")


class TestDecoder(unittest.TestCase):
    def test_decode_valid_token(self):
        token = generate_token("mysecret", {"sub": "user1", "role": "member"})["token"]
        res = decode_token(token)
        self.assertEqual(res["header"]["alg"], "HS256")
        self.assertEqual(res["payload"]["sub"], "user1")
        self.assertEqual(res["payload"]["role"], "member")


class TestAnalyzer(unittest.TestCase):
    def test_detect_alg_none(self):
        token = forge_none_token(generate_token("key", {"sub": "test"})["token"])["token"]
        decoded = decode_token(token)
        findings = analyze_token(decoded)
        severities = [f["severity"] for f in findings]
        self.assertIn(SEVERITY_CRITICAL, severities)

    def test_detect_expired_token(self):
        claims = {"sub": "test", "exp": int(time.time()) - 3600, "iss": "auth", "iat": int(time.time()) - 7200}
        token = generate_token("key", claims)["token"]
        decoded = decode_token(token)
        findings = analyze_token(decoded)
        titles = [f["title"] for f in findings]
        self.assertIn("Expired Token", titles)

    def test_detect_weak_hmac(self):
        claims = {"sub": "test", "iss": "auth", "exp": int(time.time()) + 3600, "iat": int(time.time())}
        token = generate_token("key", claims, alg="HS256")["token"]
        decoded = decode_token(token)
        findings = analyze_token(decoded)
        titles = [f["title"] for f in findings]
        self.assertIn("Weak HMAC Algorithm", titles)


class TestCracker(unittest.TestCase):
    def test_crack_successful(self):
        secret = "dragon123"
        token = generate_token(secret, {"user": "alice"})["token"]

        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write("admin\npassword\nsecret\ndragon123\n123456\n")
            path = tf.name

        try:
            res = crack_token(token, path, num_threads=2)
            self.assertTrue(res["success"])
            self.assertEqual(res["secret"], "dragon123")
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_crack_hs384_successful(self):
        secret = "topsecret"
        token = generate_token(secret, {"user": "bob"}, alg="HS384")["token"]

        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write("alpha\nbeta\ntopsecret\ngamma\n")
            path = tf.name

        try:
            res = crack_token(token, path, num_threads=2)
            self.assertTrue(res["success"])
            self.assertEqual(res["secret"], "topsecret")
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_crack_unsupported_alg(self):
        token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl"
        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write("secret\n")
            path = tf.name
        try:
            res = crack_token(token, path)
            self.assertFalse(res["success"])
            self.assertIn("not supported", res["error"])
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_crack_not_found(self):
        token = generate_token("unfindable_long_random_secret_999", {"user": "bob"})["token"]

        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write("one\ntwo\nthree\n")
            path = tf.name

        try:
            res = crack_token(token, path, num_threads=2)
            self.assertFalse(res["success"])
            self.assertIsNone(res["secret"])
        finally:
            if os.path.exists(path):
                os.remove(path)


class TestForger(unittest.TestCase):
    def test_forge_modify_claim(self):
        original = generate_token("testkey", {"sub": "user123", "role": "user"})["token"]
        forged = forge_token(original, "testkey", {"role": "admin"})

        self.assertEqual(forged["payload"]["role"], "admin")
        self.assertEqual(forged["payload"]["sub"], "user123")

        decoded = decode_token(forged["token"])
        self.assertEqual(decoded["payload"]["role"], "admin")

    def test_forge_none_algorithm(self):
        original = generate_token("testkey", {"sub": "user123"})["token"]
        forged = forge_none_token(original, {"role": "root"})
        self.assertEqual(forged["header"]["alg"], "none")
        self.assertEqual(forged["payload"]["role"], "root")
        self.assertTrue(forged["token"].endswith("."))

    def test_duration_parsing(self):
        self.assertEqual(_parse_duration("10s"), 10)
        self.assertEqual(_parse_duration("5m"), 300)
        self.assertEqual(_parse_duration("2h"), 7200)
        self.assertEqual(_parse_duration("1d"), 86400)

    def test_invalid_duration(self):
        with self.assertRaises(ValueError):
            _parse_duration("invalid")

    def test_forge_extend_exp(self):
        original = generate_token("key", {"sub": "user", "exp": 1000})["token"]
        forged = forge_token(original, "key", {}, extend_exp="1h")
        self.assertEqual(forged["payload"]["exp"], 1000 + 3600)


class TestGuiEndpoints(unittest.TestCase):
    def test_gui_html_page_exists(self):
        from jwtcrack.gui import HTML_PAGE
        self.assertIn("jwtcrack", HTML_PAGE)
        self.assertIn("Forge Admin Token", HTML_PAGE)


if __name__ == "__main__":
    unittest.main()
