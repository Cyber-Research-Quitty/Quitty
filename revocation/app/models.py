from typing import Literal, Optional, Dict, Any
from pydantic import BaseModel, Field

RevType = Literal["revoke_jti", "revoke_sub", "revoke_kid"]

class RevokeRequest(BaseModel):
    type: RevType
    value: str = Field(..., min_length=1, max_length=512)
    ttl_seconds: Optional[int] = Field(None, ge=30, le=60 * 60 * 24 * 30)

class RevokeResponse(BaseModel):
    event_id: str
    published: bool


# JWT Token Models
class TokenRequest(BaseModel):
    subject: str = Field(..., min_length=1, description="Subject (user ID) for the token")
    expires_minutes: Optional[int] = Field(None, ge=1, le=1440, description="Token expiration in minutes (default: 30)")
    additional_claims: Optional[Dict[str, Any]] = Field(None, description="Additional claims to include in the token")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    jti: str = Field(..., description="JWT ID for revocation tracking")
    subject: str


class TokenValidateRequest(BaseModel):
    token: str = Field(..., description="JWT token to validate")
    check_revocation: bool = Field(True, description="Whether to check revocation status")


class TokenValidateResponse(BaseModel):
    valid: bool
    claims: Dict[str, Any]
    revoked: bool = False
    message: str


# Refresh Token Models
class RefreshTokenRequest(BaseModel):
    subject: str = Field(..., min_length=1, description="Subject (user ID) for the token")
    client_binding: str = Field(..., min_length=1, description="Client identifier (device fingerprint, IP+UA hash, etc.)")
    additional_claims: Optional[Dict[str, Any]] = Field(None, description="Additional claims to include")


class RefreshTokenResponse(BaseModel):
    refresh_token: str
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_expires_in: int
    refresh_jti: str = Field(..., description="Refresh token JTI for revocation")
    access_jti: str = Field(..., description="Access token JTI")
    subject: str
    kyber_public_key: str = Field(..., description="Server's Kyber public key for forward secrecy")


class RefreshTokenRefreshRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh token to use")
    client_binding: str = Field(..., min_length=1, description="Current client identifier")
    client_public_key: str = Field(..., description="Client's Kyber public key (base64 encoded)")


class RefreshTokenRefreshResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = Field(None, description="New refresh token (if rotated)")
    token_type: str = "bearer"
    expires_in: int
    server_public_key: str = Field(..., description="Server's Kyber public key")
    encrypted_session_key: str = Field(..., description="Encrypted session key for forward secrecy")
    access_jti: str
    message: str = Field(default="Token refreshed successfully with Kyber forward secrecy key exchange", description="Success message")
