from typing import Literal, Optional
from pydantic import BaseModel, Field

RevType = Literal["revoke_jti", "revoke_sub", "revoke_kid"]

class RevokeRequest(BaseModel):
    type: RevType
    value: str = Field(..., min_length=1, max_length=512)
    ttl_seconds: Optional[int] = Field(None, ge=30, le=60 * 60 * 24 * 30)

class RevokeResponse(BaseModel):
    event_id: str
    published: bool
