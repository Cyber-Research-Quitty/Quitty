import json
import hashlib
import base64
from .models import JWK


def _b64url_no_pad(data: bytes) -> str:
    """Base64url encode without '=' padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def calculate_jwk_thumbprint(jwk: JWK) -> str:
    """
    Calculate RFC 7638 thumbprint for a JWK.

    For now we only support OKP (e.g. Ed25519).
    For OKP, RFC 8037 says we must use the members: crv, kty, x
    in a JSON object, sorted by key, no spaces.
    """

    if jwk.kty != "OKP":
        # Later we can add RSA/EC/PQC here.
        raise ValueError(f"Thumbprint calc only implemented for OKP keys, got kty={jwk.kty!r}")

    if jwk.crv is None or jwk.x is None:
        raise ValueError("OKP keys must have 'crv' and 'x' to compute thumbprint")

    # Build the minimal JSON object that RFC requires
    thumb_obj = {
        "crv": jwk.crv,
        "kty": jwk.kty,
        "x": jwk.x,
    }

    # Canonical JSON: keys sorted, no spaces
    thumb_json = json.dumps(thumb_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # SHA-256 hash of that JSON
    digest = hashlib.sha256(thumb_json).digest()

    # Base64url (no padding) -> this is the "jkt"
    return _b64url_no_pad(digest)
