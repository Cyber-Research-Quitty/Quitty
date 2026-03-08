from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

from .utils import b64url_decode, b64url_encode, canonical_json


@dataclass
class RootSignerInfo:
    alg: str
    public_key: str  # base64url
    kid: str


class RootSigner:
    def sign(self, msg: bytes) -> bytes: ...
    def info(self) -> RootSignerInfo: ...


class MLDsa44RootSigner(RootSigner):
    """ML-DSA-44 root signer backed by liboqs/python-oqs."""
    def __init__(self, kid: str, priv_b64: str, pub_b64: str) -> None:
        self._kid = kid
        self._priv_b64 = priv_b64
        self._pub_b64 = pub_b64

    @staticmethod
    def generate(kid: str = "root-ml-dsa-44") -> "MLDsa44RootSigner":
        import oqs  # type: ignore
        with oqs.Signature("ML-DSA-44") as sig:
            pub = sig.generate_keypair()
            priv = sig.export_secret_key()
        return MLDsa44RootSigner(kid=kid, priv_b64=b64url_encode(priv), pub_b64=b64url_encode(pub))

    def sign(self, msg: bytes) -> bytes:
        import oqs  # type: ignore
        sig = oqs.Signature("ML-DSA-44", secret_key=b64url_decode(self._priv_b64))
        return sig.sign(msg)

    def info(self) -> RootSignerInfo:
        return RootSignerInfo(alg="ml-dsa-44", public_key=self._pub_b64, kid=self._kid)

    def to_json(self) -> Dict[str, Any]:
        return {
            "alg": "ml-dsa-44",
            "kid": self._kid,
            "private_key": self._priv_b64,
            "public_key": self._pub_b64,
        }

    @staticmethod
    def from_json(obj: Dict[str, Any]) -> "MLDsa44RootSigner":
        return MLDsa44RootSigner(kid=obj["kid"], priv_b64=obj["private_key"], pub_b64=obj["public_key"])


def load_or_create_root_signer(alg: str, key_path: str) -> RootSigner:
    p = Path(key_path)

    if p.exists():
        obj = json.loads(p.read_text())
        if obj["alg"] == "ml-dsa-44":
            return MLDsa44RootSigner.from_json(obj)
        raise ValueError("Unknown stored root signer alg")

    if alg == "ml-dsa-44":
        signer = MLDsa44RootSigner.generate()
        p.write_text(json.dumps(signer.to_json(), indent=2))
        return signer

    raise ValueError("ROOT_SIGNER must be ml-dsa-44")


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

    if sig_alg == "ml-dsa-44":
        try:
            import oqs  # type: ignore
        except Exception:
            return False
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

    if sig_alg == "ml-dsa-44":
        try:
            import oqs  # type: ignore
        except Exception:
            return False
        with oqs.Signature("ML-DSA-44") as s:
            return s.verify(msg, signature, b64url_decode(pinned_pub_b64))

    return False
