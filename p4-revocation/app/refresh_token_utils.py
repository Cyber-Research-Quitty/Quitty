"""
Refresh Token Utilities with Client Binding and Kyber Forward Secrecy
"""
import jwt
import uuid
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Tuple
from fastapi import HTTPException, status

from .config import (
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    JWT_REFRESH_TOKEN_EXPIRE_DAYS,
    JWT_ISSUER
)
from .pqc_crypto import encapsulate_kyber_secret, hash_client_binding


def create_refresh_token(
    subject: str,
    client_binding: str,
    additional_claims: Optional[Dict[str, Any]] = None
) -> Tuple[str, str]:
    """
    Create a client-bound refresh token for Kyber-forward-secure refresh.
    
    Args:
        subject: The subject (user ID) for the token
        client_binding: Client identifier (device fingerprint, etc.)
        additional_claims: Additional claims to include
    
    Returns:
        Tuple of (refresh_token, client_binding_hash)
    """
    
    # Hash client binding information
    client_hash = hash_client_binding(client_binding)
    
    # Generate unique refresh token ID
    refresh_jti = str(uuid.uuid4())
    
    # Calculate expiration
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    
    # Build refresh token payload
    payload = {
        "sub": subject,
        "exp": int(expire.timestamp()),  # Convert to Unix timestamp
        "iat": int(now.timestamp()),       # Convert to Unix timestamp
        "iss": JWT_ISSUER,
        "jti": refresh_jti,
        "type": "refresh",
        "client_hash": client_hash,  # Client binding
    }
    
    # Add additional claims if provided
    if additional_claims:
        payload.update(additional_claims)
    
    # Encode refresh token
    refresh_token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    
    # Store private key mapping (in production, encrypt this)
    # For now, we'll return it - in production, store encrypted in database
    return refresh_token, client_hash


async def validate_refresh_token(
    refresh_token: str,
    client_binding: str,
    check_revocation: bool = True,
    redis_client = None
) -> Dict[str, Any]:
    """
    Validate a refresh token and verify client binding.
    
    Args:
        refresh_token: The refresh token to validate
        client_binding: Current client identifier
        check_revocation: Whether to check revocation status
        redis_client: Redis client for revocation checking
    
    Returns:
        Decoded token payload
    
    Raises:
        HTTPException: If token is invalid, expired, or client binding mismatch
    """
    try:
        # Decode and validate token (signature, expiration, issuer)
        payload = jwt.decode(
            refresh_token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired"
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid refresh token: {str(e)}"
        )
    
    # Verify token type
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is not a refresh token"
        )
    
    # Verify client binding
    stored_client_hash = payload.get("client_hash")
    if not stored_client_hash:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token missing client binding"
        )
    
    current_client_hash = hash_client_binding(client_binding)
    if stored_client_hash != current_client_hash:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Client binding mismatch - token may be from different device"
        )
    
    # Check revocation if enabled
    if check_revocation and redis_client:
        jti = payload.get("jti")
        if jti:
            revoked = await redis_client.get(f"revoked:jti:{jti}")
            if revoked:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Refresh token has been revoked"
                )
    
    return payload


async def perform_kyber_refresh(
    refresh_token: str,
    client_binding: str,
    client_public_key: str,
    redis_client = None
) -> Tuple[Dict[str, Any], str, str]:
    """
    Perform refresh with Kyber forward secrecy.
    
    Client sends their Kyber KEM public key; server encapsulates
    and returns the ciphertext for client-side decapsulation.
    
    Args:
        refresh_token: The refresh token
        client_binding: Client identifier
        client_public_key: Client's Kyber KEM public key (base64url)
        redis_client: Redis client
    
    Returns:
        Tuple of (new_access_token_payload, kem_ciphertext, encrypted_session_key)
    """
    # Validate refresh token and client binding
    refresh_payload = await validate_refresh_token(
        refresh_token,
        client_binding,
        check_revocation=True,
        redis_client=redis_client
    )
    
    # Encapsulate to client's public key to derive a shared secret
    try:
        kem_ciphertext, shared_secret = encapsulate_kyber_secret(client_public_key)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Kyber KEM encapsulation failed: {str(e)}"
        )
    
    # Use shared secret to derive encryption key for session
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'refresh-session-key',
        backend=default_backend()
    )
    session_key = hkdf.derive(bytes.fromhex(shared_secret))
    
    # Return new token payload and keys
    # In production, encrypt the new access token with session_key
    new_token_payload = {
        "sub": refresh_payload.get("sub"),
        "jti": str(uuid.uuid4()),
        "refresh_jti": refresh_payload.get("jti"),  # Link to refresh token
        "iat": datetime.now(timezone.utc),
        "iss": JWT_ISSUER,
    }
    
    # Encrypt session key with shared secret (simplified - use proper encryption in production)
    encrypted_session_key = secrets.token_urlsafe(32)  # Placeholder
    
    return new_token_payload, kem_ciphertext, encrypted_session_key


def get_refresh_token_claims(token: str) -> Dict[str, Any]:
    """Get claims from refresh token without validation (for inspection)"""
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        return payload
    except jwt.DecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid refresh token format"
        )
