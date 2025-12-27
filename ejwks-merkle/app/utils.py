from __future__ import annotations
import base64
import hashlib
import json
from typing import Any, Dict

def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def canonical_json(obj: Any) -> bytes:
    # Deterministic JSON encoding (no whitespace, sorted keys)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def jwk_thumbprint(jwk: Dict[str, Any]) -> str:
    """
    RFC 7638 thumbprint (subset depends on kty).
    Supports OKP and RSA; falls back to public fields for others.
    """
    kty = jwk.get("kty")
    if kty == "OKP":
        thumb_obj = {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}
    elif kty == "RSA":
        thumb_obj = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    else:
        thumb_obj = {k: v for k, v in jwk.items() if k not in {"d","p","q","dp","dq","qi","oth"}}
        thumb_obj["kty"] = kty
    return b64url_encode(sha256(canonical_json(thumb_obj)))
