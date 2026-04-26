"""
Refresh Token Utilities with Client Binding and Kyber Forward Secrecy
"""
import base64
import json
import jwt
import uuid
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import HTTPException, status

from .config import (
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    JWT_REFRESH_TOKEN_EXPIRE_DAYS,
    JWT_ISSUER
)
from .pqc_crypto import (
    encapsulate_kyber_secret,
    decapsulate_kyber_secret,
    hash_client_binding,
)


REFRESH_RESPONSE_AAD = b"p4-refresh-response/v1"
REFRESH_RESPONSE_KDF_INFO = b"p4-refresh-response-key/v1"
REFRESH_RESERVED_CLAIMS = {
    "sub",
    "exp",
    "iat",
    "iss",
    "jti",
    "type",
    "client_hash",
}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(encoded: str) -> bytes:
    padding = "=" * (-len(encoded) % 4)
    return base64.urlsafe_b64decode(encoded + padding)


def _derive_refresh_response_key(shared_secret_hex: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=REFRESH_RESPONSE_KDF_INFO,
    )
    return hkdf.derive(bytes.fromhex(shared_secret_hex))


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
    
    # Preserve caller-supplied claims, but never allow overrides of core refresh claims.
    if additional_claims:
        for key, value in additional_claims.items():
            if key not in REFRESH_RESERVED_CLAIMS:
                payload[key] = value
    
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
) -> Tuple[Dict[str, Any], str, bytes]:
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
        Tuple of (validated_refresh_payload, kem_ciphertext, session_key)
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

    session_key = _derive_refresh_response_key(shared_secret)
    return refresh_payload, kem_ciphertext, session_key


def extract_refresh_additional_claims(refresh_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Return caller-supplied claims that should survive refresh rotation."""
    return {
        key: value
        for key, value in refresh_payload.items()
        if key not in REFRESH_RESERVED_CLAIMS
    }


def encrypt_refresh_payload(session_key: bytes, payload: Dict[str, Any]) -> Tuple[str, str]:
    """
    Encrypt refreshed token material with the Kyber-derived session key.

    Returns:
        Tuple of (encrypted_payload_b64url, nonce_b64url)
    """
    plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(session_key).encrypt(nonce, plaintext, REFRESH_RESPONSE_AAD)
    return _b64url_encode(ciphertext), _b64url_encode(nonce)


def decrypt_refresh_payload(
    client_private_key: str,
    kem_ciphertext: str,
    encrypted_payload: str,
    payload_nonce: str,
) -> Dict[str, Any]:
    """
    Decrypt a protected refresh response using the client's private KEM key.
    """
    shared_secret = decapsulate_kyber_secret(client_private_key, kem_ciphertext)
    session_key = _derive_refresh_response_key(shared_secret)
    plaintext = AESGCM(session_key).decrypt(
        _b64url_decode(payload_nonce),
        _b64url_decode(encrypted_payload),
        REFRESH_RESPONSE_AAD,
    )
    payload = json.loads(plaintext.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Decrypted refresh payload is not an object")
    return payload


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
