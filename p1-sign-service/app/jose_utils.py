import base64
import json
from typing import Any, Dict


def b64url_encode(data: bytes) -> str:
    """
    Base64url encode without padding, as required by JOSE / JWT.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    """
    Base64url decode, adding back any missing padding.
    """
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def encode_header(header: Dict[str, Any]) -> str:
    """
    JSON-encode then base64url-encode the JOSE header.
    """
    raw = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return b64url_encode(raw)


def encode_payload(payload: Dict[str, Any]) -> str:
    """
    JSON-encode then base64url-encode the JWT payload (claims).
    """
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=False).encode("utf-8")
    return b64url_encode(raw)


def decode_segment(segment: str) -> Dict[str, Any]:
    """
    Decode a base64url-encoded JSON segment (header or payload).
    """
    raw = b64url_decode(segment)
    return json.loads(raw.decode("utf-8"))


def split_jws(token: str) -> tuple[str, str, str]:
    """
    Split a compact JWS into 3 segments.
    Raises ValueError if the structure is wrong.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed_token: expected 3 segments")
    return parts[0], parts[1], parts[2]
