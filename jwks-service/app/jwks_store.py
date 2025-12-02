from typing import Dict, Optional

from .models import JWK, JWKS
from .jwk_thumbprint import calculate_jwk_thumbprint

# ----- dummy key (as before) -----

_dummy_jwk_1 = JWK(
    kty="OKP",
    kid="demo-ed25519-1",
    alg="EdDSA",
    use="sig",
    crv="Ed25519",
    x="11qYAYpk3lC3y2GV5C7N3d2u8h2C8jv2cPZ3i8JcL1E",
)

# Index by kid and by jkt (thumbprint)
_KID_INDEX: Dict[str, JWK] = {
    _dummy_jwk_1.kid: _dummy_jwk_1,
}

_JKT_INDEX: Dict[str, JWK] = {}


def _rebuild_jkt_index() -> None:
    """Rebuild jkt → JWK mapping from all known keys."""
    _JKT_INDEX.clear()
    for jwk in _KID_INDEX.values():
        try:
            jkt = calculate_jwk_thumbprint(jwk)
        except Exception:
            # Skip keys we can't hash for now
            continue
        _JKT_INDEX[jkt] = jwk


# Build once at startup
_rebuild_jkt_index()


def add_or_update_key(jwk: JWK) -> str:
    """
    Insert or update a key coming from P1.

    - Stores by kid
    - Computes its thumbprint (jkt) and stores by jkt
    - Returns the jkt so the caller can use /jwks/by-jkt/{jkt}
    """
    jkt = calculate_jwk_thumbprint(jwk)
    _KID_INDEX[jwk.kid] = jwk
    _JKT_INDEX[jkt] = jwk
    return jkt


def get_all_keys() -> JWKS:
    """Return all keys as a JWKS (legacy /.well-known/jwks.json)."""
    return JWKS(keys=list(_KID_INDEX.values()))


def get_key_by_kid(kid: str) -> Optional[JWK]:
    """Lookup by kid."""
    return _KID_INDEX.get(kid)


def get_key_by_jkt(jkt: str) -> Optional[JWK]:
    """Lookup by thumbprint (jkt)."""
    return _JKT_INDEX.get(jkt)


def get_jkt_for_kid(kid: str) -> Optional[str]:
    """Helper mainly for debugging."""
    jwk = _KID_INDEX.get(kid)
    if jwk is None:
        return None
    return calculate_jwk_thumbprint(jwk)
