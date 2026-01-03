from __future__ import annotations
from pydantic import BaseModel, field_validator
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

    @field_validator('kid')
    @classmethod
    def validate_kid(cls, v: str) -> str:
        if not v or len(v) > 256:
            raise ValueError('kid must be between 1 and 256 characters')
        # Basic validation - alphanumeric, dash, underscore, dot
        if not all(c.isalnum() or c in '-_.' for c in v):
            raise ValueError('kid must contain only alphanumeric characters, dashes, underscores, or dots')
        return v

    @field_validator('kty')
    @classmethod
    def validate_kty(cls, v: str) -> str:
        valid_ktys = ['OKP', 'RSA', 'EC', 'oct']
        if v not in valid_ktys:
            raise ValueError(f'kty must be one of {valid_ktys}')
        return v

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
