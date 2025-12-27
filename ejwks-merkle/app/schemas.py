from __future__ import annotations
from pydantic import BaseModel
from typing import Optional, List, Dict, Any, Literal

class JWKIn(BaseModel):
    kid: str
    kty: str
    alg: Optional[str] = None

    # OKP
    crv: Optional[str] = None
    x: Optional[str] = None

    # RSA
    n: Optional[str] = None
    e: Optional[str] = None

    use: Optional[str] = None
    key_ops: Optional[List[str]] = None

    model_config = {"extra": "allow"}

class ImportKeyOut(BaseModel):
    kid: str
    jkt: str

class RootBundle(BaseModel):
    root_hash: str
    epoch: int
    sig_alg: str
    sig_kid: str
    sig_pub: str
    signature: str

class ProofItem(BaseModel):
    position: Literal["left", "right"]
    hash: str

class KeyWithProof(BaseModel):
    kid: str
    jkt: str
    jwk: Dict[str, Any]
    merkle_proof: List[ProofItem]
    root: RootBundle
