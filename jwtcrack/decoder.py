import base64
import json


def base64url_decode(data):
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def base64url_encode(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def split_token(token):
    token = token.strip()
    parts = token.split(".")
    if len(parts) not in (2, 3):
        raise ValueError(f"Invalid JWT: expected 2 or 3 parts, got {len(parts)}")
    header_b64 = parts[0]
    payload_b64 = parts[1]
    signature_b64 = parts[2] if len(parts) == 3 else ""
    return header_b64, payload_b64, signature_b64


def decode_token(token):
    header_b64, payload_b64, signature_b64 = split_token(token)

    header_json = base64url_decode(header_b64)
    header = json.loads(header_json)

    payload_json = base64url_decode(payload_b64)
    payload = json.loads(payload_json)

    signature_bytes = base64url_decode(signature_b64) if signature_b64 else b""

    return {
        "raw_token": token.strip(),
        "header_b64": header_b64,
        "payload_b64": payload_b64,
        "signature_b64": signature_b64,
        "header": header,
        "payload": payload,
        "signature": signature_bytes,
        "signing_input": f"{header_b64}.{payload_b64}",
    }
