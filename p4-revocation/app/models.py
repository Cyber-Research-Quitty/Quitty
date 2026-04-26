from typing import Literal, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

RevType = Literal["revoke_jti", "revoke_sub", "revoke_kid"]

class RevokeRequest(BaseModel):
    type: RevType
    value: str = Field(..., min_length=1, max_length=512)
    ttl_seconds: Optional[int] = Field(None, ge=30, le=60 * 60 * 24 * 30)
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"type": "revoke_jti", "value": "9f4f5f57-d620-4fd2-a352-186a6abf5988", "ttl_seconds": 30},
                {"type": "revoke_sub", "value": "alice", "ttl_seconds": 30},
                {"type": "revoke_kid", "value": "QEF6w3BaO5bBQSJhAo5B7g", "ttl_seconds": 30},
            ]
        }
    )

class RevokeResponse(BaseModel):
    event_id: str
    published: bool


class RevokeTokenRequest(BaseModel):
    token: str = Field(..., min_length=1, description="JWT token to verify via P1 and revoke by claims")
    scopes: list[Literal["jti", "sub", "kid"]] = Field(
        default_factory=lambda: ["jti", "sub", "kid"],
        description="Which values to revoke from verified token (any of: jti, sub, kid)",
    )
    ttl_seconds: Optional[int] = Field(None, ge=30, le=60 * 60 * 24 * 30)
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"token": "eyJ...<P1_access_token>...", "scopes": ["jti"], "ttl_seconds": 30},
                {"token": "eyJ...<P1_access_token>...", "scopes": ["sub"], "ttl_seconds": 30},
                {"token": "eyJ...<P1_access_token>...", "scopes": ["kid"], "ttl_seconds": 30},
                {"token": "eyJ...<P1_access_token>...", "scopes": ["jti", "sub", "kid"], "ttl_seconds": 30},
            ]
        }
    )


class RevokeTokenResponse(BaseModel):
    access_token: str = Field(..., description="The access token that was verified via P1 before revocation")
    sub: str = Field(..., description="Token subject extracted from verified P1 claims")
    jti: str = Field(..., description="Token JTI extracted from verified P1 claims")
    kid: str = Field(..., description="Token KID extracted from verified P1 header")
    revoked: Dict[str, str]
    event_ids: list[str]
    published: bool


class RevocationStatusResponse(BaseModel):
    jti: str
    revoked: bool
    revokedAt: Optional[str] = None


class RevocationCheckRequest(BaseModel):
    jti: Optional[str] = None
    sub: Optional[str] = None
    kid: Optional[str] = None


class RevocationCheckResponse(BaseModel):
    revoked: bool
    reason: Optional[Literal["jti", "sub", "kid"]] = None
    revokedAt: Optional[str] = None


class SyncP1TokenRequest(BaseModel):
    token: str = Field(..., min_length=1, description="P1-issued access token")


class SyncP1TokenResponse(BaseModel):
    access_token: str
    synced: bool
    sub: str
    jti: str
    kid: str
    alg: Optional[str] = None
    iss: Optional[str] = None


class P1TokenMetaResponse(BaseModel):
    found: bool
    sub: Optional[str] = None
    jti: str
    kid: Optional[str] = None
    alg: Optional[str] = None
    iss: Optional[str] = None
    synced_at: Optional[str] = None
    revoked: bool = False
    revocation_reason: Optional[Literal["jti", "sub", "kid"]] = None


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
    sub: str = Field(..., description="Subject from P1-issued access token")
    kid: str = Field(..., description="Signing key id from P1-issued access token header")
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
    kid: str = Field(..., description="Signing/public key id from the returned access token header")
    subject: str
    client_public_key: Optional[str] = Field(
        None,
        description="Testing-only client Kyber/ML-KEM public key generated by the server for display/demo purposes"
    )


class RefreshTokenRefreshRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh token to use")
    client_binding: str = Field(..., min_length=1, description="Current client identifier")
    client_public_key: str = Field(..., description="Client's Kyber KEM public key (base64url)")


class RefreshTokenKeyProofRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh token returned by /token/refresh/create")
    kem_ciphertext: str = Field(..., description="Ciphertext produced by encapsulating to the returned client_public_key")
    expected_shared_secret_sha256: Optional[str] = Field(
        None,
        description="Optional SHA-256 hex digest of the client-side shared secret for server-side comparison"
    )


class RefreshTokenKeyProofResponse(BaseModel):
    proof_valid: bool
    refresh_jti: str
    subject: Optional[str] = None
    kem_algorithm: str
    shared_secret_sha256: str
    matches_expected: Optional[bool] = None
    message: str


class RefreshTokenRevokeRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh token to revoke")


class RefreshTokenCheckKeypairRequest(BaseModel):
    client_public_key: str = Field(..., description="Client ML-KEM public key (base64url)")
    client_private_key: str = Field(..., description="Matching client ML-KEM private key (base64url)")


class RefreshTokenCheckKeypairResponse(BaseModel):
    match: bool
    kem_algorithm: str
    kem_ciphertext: str
    encapsulated_shared_secret: str
    decapsulated_shared_secret: str
    message: str


class RefreshTokenRefreshResponse(BaseModel):
    access_token: Optional[str] = Field(None, description="Deprecated plaintext access token; omitted for protected refresh responses")
    refresh_token: Optional[str] = Field(None, description="Deprecated plaintext refresh token; omitted for protected refresh responses")
    refresh_jti: str = Field(..., description="New refresh token JTI")
    refresh_expires_in: int = Field(..., description="Seconds until new refresh token expires")
    token_type: str = "bearer"
    expires_in: int
    kem_ciphertext: str = Field(..., description="Kyber KEM ciphertext (base64url)")
    encrypted_payload: str = Field(..., description="AES-256-GCM protected refresh response payload (base64url)")
    payload_nonce: str = Field(..., description="AES-256-GCM nonce for encrypted_payload (base64url)")
    encryption_alg: str = Field("AES-256-GCM", description="Symmetric encryption algorithm for encrypted_payload")
    kdf: str = Field("HKDF-SHA256", description="KDF used with the Kyber/ML-KEM shared secret")
    access_jti: str
