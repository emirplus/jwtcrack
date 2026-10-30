import time

WEAK_ALGORITHMS = {"HS256", "HS384", "HS512"}
STRONG_ALGORITHMS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}
REQUIRED_CLAIMS = {"iss", "exp", "iat"}

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"


def analyze_token(decoded):
    findings = []
    header = decoded["header"]
    payload = decoded["payload"]

    findings.extend(_check_algorithm(header))
    findings.extend(_check_key_confusion(header))
    findings.extend(_check_expiration(payload))
    findings.extend(_check_missing_claims(payload))
    findings.extend(_check_none_signature(header, decoded["signature_b64"]))
    findings.extend(_check_kid_injection(header))

    from jwtcrack.aspnet import is_aspnet_token, check_aspnet_issues
    if is_aspnet_token(payload):
        findings.extend(check_aspnet_issues(payload))

    return findings


def _check_algorithm(header):
    findings = []
    alg = header.get("alg", "").lower()

    if alg == "none":
        findings.append({
            "severity": SEVERITY_CRITICAL,
            "title": "Algorithm None Attack",
            "description": "Token uses 'none' algorithm — signature verification is disabled. Anyone can forge tokens without a secret.",
            "remediation": "Reject tokens with alg='none' explicitly (e.g. verify with algorithms=['HS256']).",
        })
    elif header.get("alg", "") in WEAK_ALGORITHMS:
        findings.append({
            "severity": SEVERITY_MEDIUM,
            "title": "Weak HMAC Algorithm",
            "description": f"Token uses {header['alg']} which is symmetric and vulnerable to brute-force attacks if the secret is weak.",
            "remediation": "Use a cryptographically random secret with at least 256 bits of entropy, or migrate to RS256/ES256.",
        })

    if "alg" not in header:
        findings.append({
            "severity": SEVERITY_HIGH,
            "title": "Missing Algorithm",
            "description": "No 'alg' field in header. This is non-standard and may indicate tampering.",
            "remediation": "Reject tokens without a recognized 'alg' header.",
        })

    return findings


def _check_expiration(payload):
    findings = []
    now = time.time()

    if "exp" in payload:
        try:
            exp = int(payload["exp"])
            if exp < now:
                findings.append({
                    "severity": SEVERITY_HIGH,
                    "title": "Expired Token",
                    "description": f"Token expired at {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(exp))}.",
                    "remediation": "Reject expired tokens and require re-authentication.",
                })
        except (ValueError, TypeError):
            findings.append({
                "severity": SEVERITY_MEDIUM,
                "title": "Invalid Expiration",
                "description": "The 'exp' claim is not a valid timestamp.",
                "remediation": "Ensure 'exp' claim is formatted as a valid integer Unix timestamp.",
            })

    if "nbf" in payload:
        try:
            nbf = int(payload["nbf"])
            if nbf > now:
                findings.append({
                    "severity": SEVERITY_INFO,
                    "title": "Token Not Yet Valid",
                    "description": f"Token becomes valid at {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(nbf))}.",
                    "remediation": "Wait until 'nbf' timestamp has passed before processing requests.",
                })
        except (ValueError, TypeError):
            pass

    return findings


def _check_missing_claims(payload):
    findings = []
    missing = REQUIRED_CLAIMS - set(payload.keys())

    if missing:
        findings.append({
            "severity": SEVERITY_LOW,
            "title": "Missing Recommended Claims",
            "description": f"Token is missing: {', '.join(sorted(missing))}. These claims are recommended by RFC 7519.",
            "remediation": f"Include standard claims ({', '.join(sorted(missing))}) to restrict token scope and validity.",
        })

    return findings


def _check_none_signature(header, signature_b64):
    findings = []
    alg = header.get("alg", "")

    if alg.lower() != "none" and (not signature_b64 or signature_b64 == ""):
        findings.append({
            "severity": SEVERITY_CRITICAL,
            "title": "Missing Signature",
            "description": f"Algorithm is '{alg}' but the signature is empty. This token may have been tampered with.",
            "remediation": "Reject unsigned tokens immediately during authentication checks.",
        })

    return findings


def _check_key_confusion(header):
    findings = []
    alg = header.get("alg", "").upper()
    if alg in STRONG_ALGORITHMS:
        findings.append({
            "severity": SEVERITY_INFO,
            "title": "Asymmetric Key (Potential Key Confusion)",
            "description": f"Token uses asymmetric algorithm '{alg}'. If backend fails to enforce key type, an attacker can forge tokens using HS256 with the server public key as HMAC secret (CVE-2015-9235).",
            "remediation": f"Explicitly whitelist allowed algorithms on the server (e.g. algorithms=['{alg}']) instead of trusting header 'alg'.",
        })
    return findings


def _check_kid_injection(header):
    findings = []

    if "kid" in header:
        kid = str(header["kid"])
        dangerous_chars = ["../", "..\\", "/dev/null", "'", '"', ";", "--", "union", "select", "|", "&", "`", "$", "{", "}"]
        lower_kid = kid.lower()
        for char in dangerous_chars:
            if char in lower_kid:
                findings.append({
                    "severity": SEVERITY_HIGH,
                    "title": "Potential KID Injection",
                    "description": f"The 'kid' header contains suspicious characters: '{kid}'. This may be a path traversal or injection attempt.",
                    "remediation": "Validate 'kid' against a strict internal lookup table or whitelist; never concatenate into file paths or database queries.",
                })
                break

    return findings
