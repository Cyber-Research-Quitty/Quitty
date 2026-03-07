from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .utils import b64url_decode, b64url_encode, canonical_json


@dataclass
class RootSignerInfo:
    alg: str
    public_key: str  # base64url
    kid: str


class RootSigner:
    def sign(self, msg: bytes) -> bytes: ...
    def info(self) -> RootSignerInfo: ...


class Ed25519RootSigner(RootSigner):
    def __init__(self, priv: Ed25519PrivateKey, kid: str) -> None:
        self._priv = priv
        self._pub = priv.public_key()
        self._kid = kid

    @staticmethod
    def generate(kid: str = "root-ed25519") -> "Ed25519RootSigner":
        return Ed25519RootSigner(Ed25519PrivateKey.generate(), kid=kid)

    def sign(self, msg: bytes) -> bytes:
        return self._priv.sign(msg)

    def info(self) -> RootSignerInfo:
        pub_bytes = self._pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return RootSignerInfo(alg="ed25519", public_key=b64url_encode(pub_bytes), kid=self._kid)

    def to_json(self) -> Dict[str, Any]:
        priv_bytes = self._priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return {"alg": "ed25519", "kid": self._kid, "private_key": b64url_encode(priv_bytes)}

    @staticmethod
    def from_json(obj: Dict[str, Any]) -> "Ed25519RootSigner":
        priv = Ed25519PrivateKey.from_private_bytes(b64url_decode(obj["private_key"]))
        return Ed25519RootSigner(priv, kid=obj.get("kid", "root-ed25519"))


class Dilithium2RootSigner(RootSigner):
    """
    Optional: requires python-oqs.
    Uses ML-DSA-44 (formerly known as Dilithium2) - NIST Post-Quantum Standard
    """
    def __init__(self, kid: str, priv_b64: str, pub_b64: str) -> None:
        self._kid = kid
        self._priv_b64 = priv_b64
        self._pub_b64 = pub_b64

    @staticmethod
    def generate(kid: str = "root-dilithium2") -> "Dilithium2RootSigner":
        import oqs  # type: ignore
        # Use ML-DSA-44 (the NIST standard name for Dilithium2 in liboqs 0.15+)
        with oqs.Signature("ML-DSA-44") as sig:
            pub = sig.generate_keypair()
            priv = sig.export_secret_key()
        return Dilithium2RootSigner(kid=kid, priv_b64=b64url_encode(priv), pub_b64=b64url_encode(pub))

    def sign(self, msg: bytes) -> bytes:
        import oqs  # type: ignore
        # Create signature object with the secret key
        sig = oqs.Signature("ML-DSA-44", secret_key=b64url_decode(self._priv_b64))
        return sig.sign(msg)

    def info(self) -> RootSignerInfo:
        return RootSignerInfo(alg="dilithium2", public_key=self._pub_b64, kid=self._kid)

    def to_json(self) -> Dict[str, Any]:
        return {
            "alg": "dilithium2",
            "kid": self._kid,
            "private_key": self._priv_b64,
            "public_key": self._pub_b64,
        }

    @staticmethod
    def from_json(obj: Dict[str, Any]) -> "Dilithium2RootSigner":
        return Dilithium2RootSigner(kid=obj["kid"], priv_b64=obj["private_key"], pub_b64=obj["public_key"])


def load_or_create_root_signer(alg: str, key_path: str) -> RootSigner:
    p = Path(key_path)

    if p.exists():
        obj = json.loads(p.read_text())
        if obj["alg"] == "ed25519":
            return Ed25519RootSigner.from_json(obj)
        if obj["alg"] == "dilithium2":
            return Dilithium2RootSigner.from_json(obj)
        raise ValueError("Unknown stored root signer alg")

    if alg == "ed25519":
        signer = Ed25519RootSigner.generate()
        p.write_text(json.dumps(signer.to_json(), indent=2))
        return signer

    if alg == "dilithium2":
        signer = Dilithium2RootSigner.generate()
        p.write_text(json.dumps(signer.to_json(), indent=2))
        return signer

    raise ValueError("ROOT_SIGNER must be ed25519 or dilithium2")


def sign_root_bundle(signer: RootSigner, root_b64: str, epoch: int) -> Dict[str, Any]:
    payload = {"root_hash": root_b64, "epoch": epoch}
    msg = canonical_json(payload)
    sig = signer.sign(msg)
    info = signer.info()
    return {
        **payload,
        "sig_alg": info.alg,
        "sig_kid": info.kid,
        # still included for debugging/demo; the client MUST NOT trust this in research-grade mode
        "sig_pub": info.public_key,
        "signature": b64url_encode(sig),
    }


def verify_root_bundle(bundle: Dict[str, Any]) -> bool:
    """
    INSECURE demo verification (trusts sig_pub from network).
    Keep it if you want for server-side debugging/tests.
    DO NOT use this in the verifier app.
    """
    sig_alg = bundle["sig_alg"]
    sig_pub = bundle["sig_pub"]
    signature = b64url_decode(bundle["signature"])

    payload = {"root_hash": bundle["root_hash"], "epoch": bundle["epoch"]}
    msg = canonical_json(payload)

    if sig_alg == "ed25519":
        pub = Ed25519PublicKey.from_public_bytes(b64url_decode(sig_pub))
        try:
            pub.verify(signature, msg)
            return True
        except Exception:
            return False

    if sig_alg == "dilithium2":
        try:
            import oqs  # type: ignore
        except Exception:
            return False
        # Use ML-DSA-44 (the NIST standard name for Dilithium2 in liboqs 0.15+)
        with oqs.Signature("ML-DSA-44") as s:
            return s.verify(msg, signature, b64url_decode(sig_pub))

    return False


def verify_root_bundle_pinned(bundle: Dict[str, Any], pinned_pub_b64: str) -> bool:
    """
    RESEARCH-GRADE verification:
    - Ignores bundle["sig_pub"]
    - Uses out-of-band pinned public key provided by the verifier.
    """
    sig_alg = bundle["sig_alg"]
    signature = b64url_decode(bundle["signature"])

    payload = {"root_hash": bundle["root_hash"], "epoch": bundle["epoch"]}
    msg = canonical_json(payload)

    if sig_alg == "ed25519":
        pub = Ed25519PublicKey.from_public_bytes(b64url_decode(pinned_pub_b64))
        try:
            pub.verify(signature, msg)
            return True
        except Exception:
            return False

    if sig_alg == "dilithium2":
        try:
            import oqs  # type: ignore
        except Exception:
            return False
        # Use ML-DSA-44 (the NIST standard name for Dilithium2 in liboqs 0.15+)
        with oqs.Signature("ML-DSA-44") as s:
            return s.verify(msg, signature, b64url_decode(pinned_pub_b64))

    return False
