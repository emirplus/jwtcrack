import time
from typing import Dict, Any, List

CLAIM_EXPLANATIONS = {
    "sub": ("Subject", "The unique identity of the user or entity (e.g. user ID or account ID)."),
    "iss": ("Issuer", "The authority that created and signed this token (e.g. https://auth.company.com)."),
    "aud": ("Audience", "The intended recipient or API that should accept this token."),
    "exp": ("Expiration Time", "Unix timestamp when this token becomes invalid and must be rejected."),
    "iat": ("Issued At", "Unix timestamp when this token was originally generated."),
    "nbf": ("Not Before", "Unix timestamp before which this token must not be accepted."),
    "jti": ("JWT ID", "A unique identifier for this specific token, used to prevent replay attacks."),
    "role": ("Role", "User authorization role (e.g. 'admin', 'user', 'guest') checked by backend routes."),
    "roles": ("Roles List", "Collection of roles assigned to the user."),
    "email": ("Email Address", "Email associated with the authenticated subject."),
    "name": ("Full Name", "Display name of the user."),
}

LABS = [
    {
        "id": 1,
        "title": "The Weak Password",
        "difficulty": "Beginner",
        "category": "Brute-Force",
        "objective": "Crack the weak HMAC signing secret using the common wordlist.",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDAxIiwibmFtZSI6IkFsaWNlIiwicm9sZSI6InVzZXIifQ.Nf-N8lV47i431r8qj9Yl5lU8Yd4ZpA2nC3mK7sX0eWs",
        "hint": "Run: jwtcrack crack <token> -w wordlists/common.txt",
        "solution": "Secret is 'dragon'. You can now forge any claim using this secret.",
    },
    {
        "id": 2,
        "title": "The Trusting Server (alg: none)",
        "difficulty": "Beginner",
        "category": "Signature Bypass",
        "objective": "Elevate your role from 'user' to 'admin' without knowing the signing key by forcing algorithm 'none'.",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyMDAyIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MDAwMDAwMDB9.xV7k8W2e9zL4pQ1mN5bV3cR6tY8uI0oP2aS4dF6gH8j",
        "hint": "Use the GUI forge tool with an empty secret, or python -m jwtcrack forge with alg:none.",
        "solution": "Header becomes {'alg': 'none', 'typ': 'JWT'} and signature is stripped.",
    },
    {
        "id": 3,
        "title": "Time Traveler (Expiration Tampering)",
        "difficulty": "Beginner",
        "category": "Claim Forgery",
        "objective": "The target token expired years ago. Extend its expiration timestamp into the future.",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIzMDAzIiwicm9sZSI6ImVkaXRvciIsImV4cCI6MTU3NzgzNjgwMH0.8vL2_qY3xP7nK5sR9bW1cZ4mN6tY8uI0oP2aS4dF6gH",
        "hint": "Run: jwtcrack forge <token> -s secret123 --extend-exp 24h",
        "solution": "Updating 'exp' claim and recalculating HMAC produces a valid token accepted by timestamp filters.",
    },
    {
        "id": 4,
        "title": "Asymmetric Confusion (RS256 -> HS256)",
        "difficulty": "Intermediate",
        "category": "Key Confusion (CVE-2015-9235)",
        "objective": "A vulnerable server verifies RS256 tokens using HMAC when 'alg: HS256' is sent, passing its public RSA certificate as the HMAC secret.",
        "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MDA0Iiwicm9sZSI6InZpZXdlciJ9.fakeSigRSA",
        "hint": "Run: jwtcrack exploit <token> --attack key-confusion --public-key sample_pubkey.pem --claims '{\"role\":\"admin\"}'",
        "solution": "The forged token uses HS256 with the public key bytes as HMAC secret.",
    },
    {
        "id": 5,
        "title": "The Microsoft Maze (ASP.NET Role Desync)",
        "difficulty": "Intermediate",
        "category": "Claim Confusion",
        "objective": "Inject both standard and Microsoft XML schema role URIs to test for backend middleware desynchronization.",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1MDA1Iiwicm9sZSI6InVzZXIifQ.fakeSigASP",
        "hint": "Run: jwtcrack forge <token> -s secret --claims '{\"role\":\"Admin\"}' --aspnet",
        "solution": "Generates both standard and 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role' claims.",
    },
]


def explain_token(decoded: Dict[str, Any]) -> Dict[str, Any]:
    header = decoded.get("header", {})
    payload = decoded.get("payload", {})
    alg = header.get("alg", "Unknown")

    if alg.startswith("HS"):
        alg_type = "Symmetric (HMAC)"
        alg_detail = (
            f"{alg} uses a single shared secret key for BOTH signing and verification. "
            "If an attacker discovers this secret (e.g. through a dictionary attack), they can forge any token."
        )
    elif alg.startswith("RS") or alg.startswith("PS") or alg.startswith("ES"):
        alg_type = "Asymmetric (Public/Private Keypair)"
        alg_detail = (
            f"{alg} uses a private key on the auth server to sign, and a public key on resource servers to verify. "
            "However, if the server doesn't enforce the algorithm type, it may be vulnerable to RS->HS Key Confusion."
        )
    elif alg.lower() == "none":
        alg_type = "Insecure / None"
        alg_detail = "Signature is completely absent. Any client can modify claims without rejection."
    else:
        alg_type = "Unknown"
        alg_detail = f"Algorithm '{alg}' is unrecognized."

    claim_details = []
    now = time.time()
    for key, value in payload.items():
        if key in CLAIM_EXPLANATIONS:
            title, desc = CLAIM_EXPLANATIONS[key]
        else:
            title = "Custom Claim"
            desc = f"Application-specific property '{key}' used by backend business logic."

        extra = None
        if key in ("exp", "iat", "nbf"):
            try:
                ts = int(value)
                human_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))
                if key == "exp":
                    status = "EXPIRED" if ts < now else "ACTIVE"
                    extra = f"{human_time} ({status})"
                else:
                    extra = human_time
            except (ValueError, TypeError):
                extra = "Invalid timestamp"

        claim_details.append({
            "key": key,
            "value": value,
            "title": title,
            "description": desc,
            "human_readable": extra,
        })

    return {
        "algorithm": alg,
        "algorithm_type": alg_type,
        "algorithm_detail": alg_detail,
        "claims": claim_details,
    }


def list_labs() -> List[Dict[str, Any]]:
    return LABS


def get_lab(lab_id: int) -> Dict[str, Any]:
    for lab in LABS:
        if lab["id"] == lab_id:
            return lab
    raise ValueError(f"Lab ID {lab_id} not found. Available labs: 1 to {len(LABS)}")
