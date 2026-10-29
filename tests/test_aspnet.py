import unittest
from jwtcrack.aspnet import (
    ASPNET_TO_STANDARD,
    STANDARD_TO_ASPNET,
    is_aspnet_token,
    normalize_aspnet_claims,
    to_aspnet_claims,
    check_aspnet_issues,
)
from jwtcrack.forger import generate_token, forge_token
from jwtcrack.decoder import decode_token
from jwtcrack.analyzer import analyze_token


class TestAspNetModule(unittest.TestCase):
    def test_schema_mapping_consistency(self):
        self.assertIn("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", ASPNET_TO_STANDARD)
        self.assertEqual(ASPNET_TO_STANDARD["http://schemas.microsoft.com/ws/2008/06/identity/claims/role"], "role")
        self.assertEqual(STANDARD_TO_ASPNET["role"], "http://schemas.microsoft.com/ws/2008/06/identity/claims/role")

    def test_is_aspnet_token(self):
        aspnet_payload = {
            "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "Admin",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": "testuser",
        }
        standard_payload = {
            "sub": "12345",
            "role": "Admin",
        }
        self.assertTrue(is_aspnet_token(aspnet_payload))
        self.assertFalse(is_aspnet_token(standard_payload))
        self.assertFalse(is_aspnet_token("invalid"))
        self.assertFalse(is_aspnet_token(None))

    def test_normalize_aspnet_claims(self):
        payload = {
            "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "Manager",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": "alice",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": "user-001",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "alice@example.com",
            "custom_claim": 42,
        }
        normalized = normalize_aspnet_claims(payload)
        self.assertEqual(normalized["role"], "Manager")
        self.assertEqual(normalized["name"], "alice")
        self.assertEqual(normalized["sub"], "user-001")
        self.assertEqual(normalized["email"], "alice@example.com")
        self.assertEqual(normalized["custom_claim"], 42)
        self.assertEqual(normalize_aspnet_claims("not-a-dict"), "not-a-dict")

    def test_to_aspnet_claims(self):
        std_claims = {
            "role": "Admin",
            "sub": "user-99",
            "email": "user@example.com",
            "custom": "test",
        }
        aspnet_claims = to_aspnet_claims(std_claims)
        self.assertEqual(aspnet_claims["http://schemas.microsoft.com/ws/2008/06/identity/claims/role"], "Admin")
        self.assertEqual(aspnet_claims["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"], "user-99")
        self.assertEqual(aspnet_claims["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"], "user@example.com")
        self.assertEqual(aspnet_claims["custom"], "test")
        self.assertEqual(to_aspnet_claims("not-a-dict"), "not-a-dict")

    def test_check_aspnet_role_incompatibility(self):
        payload = {
            "sub": "user-1",
            "role": "Admin",
        }
        findings = check_aspnet_issues(payload)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[0]["title"], "ASP.NET Core Role Incompatibility")

    def test_check_aspnet_role_claim_confusion(self):
        payload = {
            "role": "User",
            "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "Admin",
        }
        findings = check_aspnet_issues(payload)
        confusion_findings = [f for f in findings if f["title"] == "ASP.NET Core Role Claim Confusion"]
        self.assertEqual(len(confusion_findings), 1)
        self.assertEqual(confusion_findings[0]["severity"], "MEDIUM")

    def test_check_aspnet_mixed_identity_schema(self):
        payload = {
            "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "Admin",
            "sub": "user-42",
        }
        findings = check_aspnet_issues(payload)
        mixed_findings = [f for f in findings if f["title"] == "Mixed Identity Schema"]
        self.assertEqual(len(mixed_findings), 1)
        self.assertEqual(mixed_findings[0]["severity"], "LOW")

    def test_generate_token_with_aspnet_flag(self):
        secret = "supersecretkey123"
        claims = {"role": "Admin", "name": "alice", "sub": "123"}
        res = generate_token(secret, claims, as_aspnet=True)
        decoded = decode_token(res["token"])
        payload = decoded["payload"]
        self.assertIn("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", payload)
        self.assertEqual(payload["http://schemas.microsoft.com/ws/2008/06/identity/claims/role"], "Admin")
        self.assertIn("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", payload)
        self.assertEqual(payload["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"], "alice")

    def test_forge_token_with_aspnet_flag(self):
        secret = "supersecretkey123"
        base_res = generate_token(secret, {"sub": "123", "role": "User"})
        forged_res = forge_token(base_res["token"], secret, {"role": "SuperAdmin"}, as_aspnet=True)
        decoded = decode_token(forged_res["token"])
        payload = decoded["payload"]
        self.assertIn("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", payload)
        self.assertEqual(payload["http://schemas.microsoft.com/ws/2008/06/identity/claims/role"], "SuperAdmin")

    def test_analyzer_integration_with_aspnet(self):
        secret = "supersecretkey123"
        res = generate_token(secret, {
            "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "Admin",
            "role": "User",
        })
        decoded = decode_token(res["token"])
        findings = analyze_token(decoded)
        titles = [f["title"] for f in findings]
        self.assertIn("ASP.NET Core Role Claim Confusion", titles)


    def test_cfdj8_cookie_detection(self):
        cookie = "CfDJ8KpBAVaTUwBDvRoHFzP"
        with self.assertRaises(ValueError) as ctx:
            decode_token(cookie)
        self.assertIn("ASP.NET Core Data Protection encrypted ticket/cookie", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
