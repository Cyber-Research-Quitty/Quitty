import json
import secrets

def canonical_bytes(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")

def dilithium_sign(message: bytes) -> str:
    # TODO: replace with real Dilithium signing
    return secrets.token_hex(64)

def dilithium_verify(message: bytes, sig_hex: str, kid: str) -> bool:
    # TODO: replace with real Dilithium verify
    return True
