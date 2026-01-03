"""
JWT Token Generation and Validation Utilities
"""
import jwt
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Tuple
from fastapi import HTTPException, status

from .config import (
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
    JWT_ISSUER
)


def create_access_token(
    subject: str,
    additional_claims: Optional[Dict[str, Any]] = None,
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT access token.
    
    Args:
        subject: The subject (user ID) for the token
        additional_claims: Additional claims to include in the token
        expires_delta: Custom expiration time delta. If None, uses default from config.
    
    Returns:
        Encoded JWT token string
    """
    now = datetime.now(timezone.utc)
    
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Generate a unique JTI (JWT ID) for this token
    jti = str(uuid.uuid4())
    
    # Standard JWT claims
    # Note: PyJWT accepts datetime objects for exp/iat, but we'll use timestamps for consistency
    payload = {
        "sub": subject,
        "exp": int(expire.timestamp()),  # Convert to Unix timestamp
        "iat": int(now.timestamp()),      # Convert to Unix timestamp
        "iss": JWT_ISSUER,
        "jti": jti,  # JWT ID for revocation tracking
        "type": "access"
    }
    
    # Add additional claims if provided
    if additional_claims:
        payload.update(additional_claims)
    
    # Encode and return the token
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> Dict[str, Any]:
    """
    Decode and validate a JWT token.
    
    Args:
        token: The JWT token string to decode
    
    Returns:
        Decoded token payload
    
    Raises:
        HTTPException: If token is invalid, expired, or malformed
    """
    try:
        # Decode with verification - PyJWT automatically checks exp claim
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            options={"verify_signature": True, "verify_exp": True, "verify_iss": True}
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.InvalidIssuerError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token issuer"
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )


def get_token_claims(token: str) -> Dict[str, Any]:
    """
    Get claims from a token without full validation (for inspection).
    Note: This does not verify the signature, use decode_token for validation.
    
    Args:
        token: The JWT token string
    
    Returns:
        Decoded token payload (unverified)
    """
    try:
        # Decode without verification (for inspection only)
        payload = jwt.decode(token, options={"verify_signature": False})
        return payload
    except jwt.DecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token format"
        )


async def is_token_revoked(
    token_payload: Dict[str, Any],
    redis_client
) -> Tuple[bool, Optional[str]]:
    """
    Check if a token is revoked by checking Redis cache.
    Checks for revocation by jti, sub, or kid.
    
    Args:
        token_payload: Decoded JWT payload
        redis_client: Redis client instance
    
    Returns:
        Tuple of (is_revoked: bool, reason: Optional[str])
        reason indicates why it was revoked: "jti", "sub", or "kid"
    """
    if not redis_client:
        return False, None
    
    # Check revocation by JTI (JWT ID) - most specific check first
    jti = token_payload.get("jti")
    if jti:
        revoked_jti = await redis_client.get(f"revoked:jti:{jti}")
        if revoked_jti:
            return True, "jti"
    
    # Check revocation by subject
    sub = token_payload.get("sub")
    if sub:
        revoked_sub = await redis_client.get(f"revoked:sub:{sub}")
        if revoked_sub:
            return True, "sub"
    
    # Check revocation by KID (if present in token)
    kid = token_payload.get("kid")
    if kid:
        revoked_kid = await redis_client.get(f"revoked:kid:{kid}")
        if revoked_kid:
            return True, "kid"
    
    return False, None


async def validate_token(
    token: str,
    redis_client,
    check_revocation: bool = True
) -> Dict[str, Any]:
    """
    Validate a JWT token including signature, expiration, and revocation status.
    
    Args:
        token: The JWT token string to validate
        redis_client: Redis client for revocation checking
        check_revocation: Whether to check revocation status
    
    Returns:
        Decoded and validated token payload
    
    Raises:
        HTTPException: If token is invalid, expired, or revoked
    """
    # First, decode without validation to check revocation (even for expired tokens)
    # This ensures revocation takes precedence over expiration
    claims_for_revocation_check = None
    if check_revocation:
        try:
            # Decode without verification to get claims for revocation check
            claims_for_revocation_check = jwt.decode(token, options={"verify_signature": False})
            
            # Check revocation status before expiration check
            is_revoked, reason = await is_token_revoked(claims_for_revocation_check, redis_client)
            if is_revoked:
                if reason == "sub":
                    detail = "Token has been revoked (all tokens for this subject are revoked)"
                elif reason == "kid":
                    detail = "Token has been revoked (all tokens for this key are revoked)"
                else:
                    detail = "Token has been revoked"
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=detail
                )
        except HTTPException:
            # Re-raise revocation-related exceptions
            raise
        except Exception:
            # If we can't decode even for revocation check, continue to full validation
            pass
    
    # Now decode and validate token (signature, expiration, issuer)
    payload = decode_token(token)
    
    return payload


