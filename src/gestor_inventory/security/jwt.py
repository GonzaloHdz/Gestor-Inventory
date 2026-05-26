import base64
import hashlib
import hmac
import json
import time
from typing import Any


def create_jwt_hs256(payload: dict[str, Any], *, secret: str, expires_in_seconds: int) -> str:
    now = int(time.time())
    body = dict(payload)
    body.setdefault("iat", now)
    body.setdefault("exp", now + int(expires_in_seconds))

    header_b64 = _b64url_encode_json({"alg": "HS256", "typ": "JWT"})
    payload_b64 = _b64url_encode_json(body)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    signature_b64 = _b64url_encode_bytes(signature)
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def verify_jwt_hs256(token: str, *, secret: str) -> dict[str, Any]:
    header_b64, payload_b64, signature_b64 = token.split(".", 2)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    provided = _b64url_decode(signature_b64)
    if not hmac.compare_digest(expected, provided):
        raise ValueError("invalid signature")

    payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    exp = payload.get("exp")
    if isinstance(exp, int) and int(time.time()) > exp:
        raise ValueError("token expired")
    return payload


def _b64url_encode_json(obj: Any) -> str:
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _b64url_encode_bytes(raw)


def _b64url_encode_bytes(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
