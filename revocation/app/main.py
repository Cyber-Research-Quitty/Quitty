# app/main.py
import json
import uuid
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

import redis.asyncio as redis
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .config import (
    REDIS_URL, PQC_SIGNING_KEY_ID, JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
    JWT_REFRESH_TOKEN_EXPIRE_DAYS
)
from .store_sqlite import (
    init_sqlite, insert_event, insert_refresh_token, update_refresh_token_usage,
    revoke_refresh_token, insert_token_event
)
from .pqc_crypto import canonical_bytes, dilithium_sign
from .kafka_pub import start_producer, publish_event, publish_token_event
from .jwt_utils import create_access_token, validate_token, get_token_claims, is_token_revoked
from .refresh_token_utils import (
    create_refresh_token, validate_refresh_token, perform_kyber_refresh,
    get_refresh_token_claims
)
from .models import (
    RevokeRequest,
    RevokeResponse,
    TokenRequest,
    TokenResponse,
    TokenValidateRequest,
    TokenValidateResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
    RefreshTokenRefreshRequest,
    RefreshTokenRefreshResponse
)

app = FastAPI(title="P4 Enhanced Secure Revocation (SQLite)", version="1.0")

# Runtime handles
rds: Optional[redis.Redis] = None
producer = None


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# -------------------------
# Startup / Shutdown
# -------------------------
@app.on_event("startup")
async def startup():
    global rds, producer
    init_sqlite()
    rds = redis.from_url(REDIS_URL, decode_responses=True)
    producer = await start_producer()


@app.on_event("shutdown")
async def shutdown():
    global rds, producer
    if producer:
        await producer.stop()
    if rds:
        await rds.close()


# -------------------------
# Routes
# -------------------------
@app.get("/")
async def root():
    # helpful so you don't see 404 at /
    return {"service": "p4-revocation", "status": "running", "docs": "/docs"}


@app.get("/health")
async def health():
    # this is the route you were testing
    return {"ok": True}


@app.post("/revoke", response_model=RevokeResponse)
async def revoke(req: RevokeRequest):
    global rds, producer
    if not rds or not producer:
        raise HTTPException(status_code=503, detail="Service not ready")

    event_id = str(uuid.uuid4())
    nonce = secrets.token_urlsafe(16)
    ts = utc_now_iso()

    unsigned = {
        "event_id": event_id,
        "type": req.type,
        "value": req.value,
        "ts": ts,
        "nonce": nonce,
        "kid": PQC_SIGNING_KEY_ID,
    }
    sig = dilithium_sign(canonical_bytes(unsigned))

    event = dict(unsigned)
    event["sig"] = sig

    # 1) Durable audit log (SQLite)
    insert_event(event)

    # 2) Fast enforcement cache (Redis)
    keyspace = req.type.split("_")[1]  # jti/sub/kid
    redis_key = f"revoked:{keyspace}:{req.value}"

    if req.ttl_seconds:
        await rds.setex(redis_key, req.ttl_seconds, "1")
    else:
        await rds.set(redis_key, "1")

    # 3) Broadcast to other services (Kafka)
    await publish_event(producer, canonical_bytes(event))

    return RevokeResponse(event_id=event_id, published=True)


@app.post("/token", response_model=TokenResponse)
async def create_token(req: TokenRequest):
    """
    Generate a new JWT access token.
    
    - **subject**: The subject (user ID) for the token
    - **expires_minutes**: Optional custom expiration time in minutes
    - **additional_claims**: Optional additional claims to include in the token
    """
    global rds
    if not rds:
        raise HTTPException(status_code=503, detail="Service not ready")
    
    # Calculate expiration delta if custom expiration is provided
    expires_delta = None
    if req.expires_minutes:
        expires_delta = timedelta(minutes=req.expires_minutes)
    
    # Create the access token
    token = create_access_token(
        subject=req.subject,
        additional_claims=req.additional_claims,
        expires_delta=expires_delta
    )
    
    # Decode to get the JTI and expiration
    claims = get_token_claims(token)
    jti = claims.get("jti")
    exp = claims.get("exp")
    
    # Calculate expires_in (seconds until expiration)
    if exp:
        expires_in = int(exp - datetime.now(timezone.utc).timestamp())
    else:
        expires_in = JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=expires_in,
        jti=jti,
        subject=req.subject
    )


@app.post("/token/validate", response_model=TokenValidateResponse)
async def validate_token_endpoint(req: TokenValidateRequest):
    """
    Validate a JWT token and check revocation status.
    
    - **token**: The JWT token to validate
    - **check_revocation**: Whether to check if the token has been revoked
    """
    global rds
    if not rds:
        raise HTTPException(status_code=503, detail="Service not ready")
    
    try:
        # Validate the token (signature, expiration, issuer)
        payload = await validate_token(
            token=req.token,
            redis_client=rds,
            check_revocation=req.check_revocation
        )
        
        return TokenValidateResponse(
            valid=True,
            claims=payload,
            revoked=False,
            message="Token is valid and not revoked"
        )
    except HTTPException as e:
        # Token validation failed - could be expired, invalid, or revoked
        try:
            # Try to decode without validation to get claims for inspection
            claims = get_token_claims(req.token)
            
            # Check if it's actually revoked (separate from expiration)
            is_revoked = False
            revocation_reason = None
            if req.check_revocation:
                is_revoked, revocation_reason = await is_token_revoked(claims, rds)
            
            # Determine the actual reason for failure
            # If validate_token raised a revocation exception, use that message
            error_message = e.detail
            
            # Check if token is expired by examining exp claim
            exp_claim = claims.get("exp")
            is_expired = False
            if exp_claim:
                current_time = int(datetime.now(timezone.utc).timestamp())
                is_expired = exp_claim < current_time
            
            # Prioritize revocation message if token is revoked
            # (validate_token now checks revocation first, so this should already be set)
            if is_revoked:
                if "revoked" not in error_message.lower():
                    # Revocation wasn't detected in validate_token, set it now
                    if revocation_reason == "sub":
                        error_message = "Token has been revoked (all tokens for this subject are revoked)"
                    elif revocation_reason == "kid":
                        error_message = "Token has been revoked (all tokens for this key are revoked)"
                    else:
                        error_message = "Token has been revoked"
                    
                    # If also expired, mention both
                    if is_expired:
                        if revocation_reason == "sub":
                            error_message = "Token has expired and been revoked (all tokens for this subject are revoked)"
                        else:
                            error_message = "Token has expired and been revoked"
            elif is_expired:
                # Only expired, not revoked
                time_expired = int(datetime.now(timezone.utc).timestamp()) - exp_claim
                error_message = f"Token has expired ({time_expired} seconds ago)"
            
            return TokenValidateResponse(
                valid=False,
                claims=claims,
                revoked=is_revoked,
                message=error_message
            )
        except Exception:
            # Can't even decode the token
            return TokenValidateResponse(
                valid=False,
                claims={},
                revoked=False,
                message=e.detail
            )


@app.get("/token/inspect")
async def inspect_token(token: str):
    """
    Inspect a JWT token without full validation (for debugging).
    Returns the token claims without verifying signature or expiration.
    """
    try:
        claims = get_token_claims(token)
        
        # Check revocation status for debugging
        is_revoked = False
        revocation_reason = None
        if rds:
            is_revoked, revocation_reason = await is_token_revoked(claims, rds)
        
        return {
            "claims": claims,
            "revoked": is_revoked,
            "revocation_reason": revocation_reason,
            "note": "This is an unverified inspection. Use /token/validate for full validation."
        }
    except HTTPException as e:
        raise e


@app.post("/token/refresh/create", response_model=RefreshTokenResponse)
async def create_refresh_token_endpoint(req: RefreshTokenRequest):
    """
    Create a new refresh token with client binding and Kyber forward secrecy.
    
    - **subject**: The subject (user ID) for the token
    - **client_binding**: Client identifier (device fingerprint, IP+UA hash, etc.)
    - **additional_claims**: Optional additional claims
    
    Returns both access token and refresh token with Kyber public key.
    """
    global rds, producer
    if not rds or not producer:
        raise HTTPException(status_code=503, detail="Service not ready")
    
    event_id = str(uuid.uuid4())
    ts = utc_now_iso()
    
    # Create refresh token with client binding
    refresh_token, kyber_public_key, client_hash = create_refresh_token(
        subject=req.subject,
        client_binding=req.client_binding,
        additional_claims=req.additional_claims
    )
    
    # Get refresh token claims
    refresh_claims = get_refresh_token_claims(refresh_token)
    refresh_jti = refresh_claims.get("jti")
    refresh_exp = refresh_claims.get("exp")
    
    # Create access token
    access_token = create_access_token(
        subject=req.subject,
        additional_claims=req.additional_claims
    )
    access_claims = get_token_claims(access_token)
    access_jti = access_claims.get("jti")
    access_exp = access_claims.get("exp")
    
    # Calculate expiration times
    if refresh_exp:
        refresh_expires_in = int(refresh_exp - datetime.now(timezone.utc).timestamp())
    else:
        refresh_expires_in = JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    
    if access_exp:
        access_expires_in = int(access_exp - datetime.now(timezone.utc).timestamp())
    else:
        access_expires_in = JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    
    # Store refresh token in SQLite audit log
    expires_at = datetime.fromtimestamp(refresh_exp, tz=timezone.utc).isoformat() if refresh_exp else None
    if expires_at:
        insert_refresh_token(
            token_id=refresh_jti,
            subject=req.subject,
            client_hash=client_hash,
            kyber_public_key=kyber_public_key,
            created_at=ts,
            expires_at=expires_at
        )
    
    # Cache refresh token in Redis
    refresh_redis_key = f"refresh_token:{refresh_jti}"
    await rds.setex(
        refresh_redis_key,
        refresh_expires_in,
        json.dumps({
            "subject": req.subject,
            "client_hash": client_hash,
            "kyber_pub": kyber_public_key
        })
    )
    
    # Publish token creation event to Kafka
    token_event = {
        "event_id": event_id,
        "event_type": "refresh_token_created",
        "token_id": refresh_jti,
        "subject": req.subject,
        "client_hash": client_hash,
        "ts": ts,
        "nonce": secrets.token_urlsafe(16),
        "kid": PQC_SIGNING_KEY_ID,
    }
    token_event["sig"] = dilithium_sign(canonical_bytes(token_event))
    
    # Audit log
    insert_token_event(
        event_id=event_id,
        event_type="refresh_token_created",
        token_id=refresh_jti,
        subject=req.subject,
        ts=ts,
        data=json.dumps({"client_hash": client_hash}),
        published=True
    )
    
    # Publish to Kafka
    await publish_token_event(producer, canonical_bytes(token_event))
    
    return RefreshTokenResponse(
        refresh_token=refresh_token,
        access_token=access_token,
        token_type="bearer",
        expires_in=access_expires_in,
        refresh_expires_in=refresh_expires_in,
        refresh_jti=refresh_jti,
        access_jti=access_jti,
        subject=req.subject,
        kyber_public_key=kyber_public_key
    )


@app.post("/token/refresh", response_model=RefreshTokenRefreshResponse)
async def refresh_token_endpoint(req: RefreshTokenRefreshRequest):
    """
    Refresh access token using refresh token with Kyber forward secrecy.
    
    - **refresh_token**: The refresh token
    - **client_binding**: Current client identifier (must match original)
    - **client_public_key**: Client's Kyber public key for forward secrecy
    
    Returns new access token with Kyber-encrypted session key.
    """
    global rds, producer
    if not rds or not producer:
        raise HTTPException(status_code=503, detail="Service not ready")
    
    event_id = str(uuid.uuid4())
    ts = utc_now_iso()
    
    # Perform Kyber-based refresh
    try:
        new_token_payload, server_public_key, encrypted_session_key = await perform_kyber_refresh(
            refresh_token=req.refresh_token,
            client_binding=req.client_binding,
            client_public_key=req.client_public_key,
            redis_client=rds
        )
    except HTTPException:
        raise
    
    # Get refresh token claims
    refresh_claims = get_refresh_token_claims(req.refresh_token)
    refresh_jti = refresh_claims.get("jti")
    subject = refresh_claims.get("sub")
    
    # Create new access token
    access_token = create_access_token(
        subject=subject,
        additional_claims={"refresh_jti": refresh_jti}
    )
    access_claims = get_token_claims(access_token)
    access_jti = access_claims.get("jti")
    access_exp = access_claims.get("exp")
    
    # Calculate expiration
    if access_exp:
        expires_in = int(access_exp - datetime.now(timezone.utc).timestamp())
    else:
        expires_in = JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    
    # Update refresh token last used timestamp
    update_refresh_token_usage(refresh_jti, ts)
    
    # Update Redis cache
    refresh_redis_key = f"refresh_token:{refresh_jti}"
    cached_data = await rds.get(refresh_redis_key)
    if cached_data:
        # Update last used in cache
        import json
        data = json.loads(cached_data)
        data["last_used"] = ts
        await rds.setex(refresh_redis_key, JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60, json.dumps(data))
    
    # Publish refresh event to Kafka
    refresh_event = {
        "event_id": event_id,
        "event_type": "token_refreshed",
        "token_id": refresh_jti,
        "subject": subject,
        "new_access_jti": access_jti,
        "ts": ts,
        "nonce": secrets.token_urlsafe(16),
        "kid": PQC_SIGNING_KEY_ID,
    }
    refresh_event["sig"] = dilithium_sign(canonical_bytes(refresh_event))
    
    # Audit log
    insert_token_event(
        event_id=event_id,
        event_type="token_refreshed",
        token_id=refresh_jti,
        subject=subject,
        ts=ts,
        data=json.dumps({"new_access_jti": access_jti}),
        published=True
    )
    
    # Publish to Kafka
    await publish_token_event(producer, canonical_bytes(refresh_event))
    
    return RefreshTokenRefreshResponse(
        access_token=access_token,
        refresh_token=None,  # Token rotation can be added later
        token_type="bearer",
        expires_in=expires_in,
        server_public_key=server_public_key,
        encrypted_session_key=encrypted_session_key,
        access_jti=access_jti
    )


@app.post("/token/refresh/revoke", response_model=RevokeResponse)
async def revoke_refresh_token_endpoint(refresh_token: str):
    """
    Revoke a refresh token.
    This will invalidate the refresh token and prevent future use.
    """
    global rds, producer
    if not rds or not producer:
        raise HTTPException(status_code=503, detail="Service not ready")
    
    # Get refresh token claims
    try:
        refresh_claims = get_refresh_token_claims(refresh_token)
        refresh_jti = refresh_claims.get("jti")
        if not refresh_jti:
            raise HTTPException(status_code=400, detail="Invalid refresh token")
    except:
        raise HTTPException(status_code=400, detail="Invalid refresh token format")
    
    event_id = str(uuid.uuid4())
    nonce = secrets.token_urlsafe(16)
    ts = utc_now_iso()
    
    # Create revocation event
    unsigned = {
        "event_id": event_id,
        "type": "revoke_jti",
        "value": refresh_jti,
        "ts": ts,
        "nonce": nonce,
        "kid": PQC_SIGNING_KEY_ID,
    }
    sig = dilithium_sign(canonical_bytes(unsigned))
    
    event = dict(unsigned)
    event["sig"] = sig
    
    # 1) Durable audit log (SQLite)
    insert_event(event)
    revoke_refresh_token(refresh_jti, ts)
    
    # 2) Fast enforcement cache (Redis)
    redis_key = f"revoked:jti:{refresh_jti}"
    await rds.set(redis_key, "1")
    
    # Also remove from refresh token cache
    await rds.delete(f"refresh_token:{refresh_jti}")
    
    # 3) Broadcast to other services (Kafka)
    await publish_event(producer, canonical_bytes(event))
    
    # Also publish token event
    token_event = {
        "event_id": str(uuid.uuid4()),
        "event_type": "refresh_token_revoked",
        "token_id": refresh_jti,
        "subject": refresh_claims.get("sub"),
        "ts": ts,
        "nonce": secrets.token_urlsafe(16),
        "kid": PQC_SIGNING_KEY_ID,
    }
    token_event["sig"] = dilithium_sign(canonical_bytes(token_event))
    await publish_token_event(producer, canonical_bytes(token_event))
    
    return RevokeResponse(event_id=event_id, published=True)
