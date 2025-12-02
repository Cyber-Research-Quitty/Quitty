from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

class JWK(BaseModel):
    kty: str
    kid: str
    alg: str
    use: str = "sig"
    crv: Optional[str] = None
    x: Optional[str] = None

    # extra metadata from P1
    created_at: Optional[datetime] = Field(default=None, alias="createdAt")

    class Config:
        populate_by_name = True


class JWKS(BaseModel):
    keys: List[JWK]

class PublicKeyExport(BaseModel):
    kid: str
    alg: str
    kty: str
    crv: Optional[str] = None
    x: str
    created_at: Optional[datetime] = Field(default=None, alias="createdAt")

    class Config:
        populate_by_name = True
