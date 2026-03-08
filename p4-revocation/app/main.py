# app/main.py
import json
import uuid
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional
import base64

import redis.asyncio as redis
from fastapi import FastAPI, HTTPException

from .config import (
    REDIS_URL, PQC_SIGNING_KEY_ID, JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
    JWT_REFRESH_TOKEN_EXPIRE_DAYS, ACCESS_TOKEN_PROVIDER,
    P1_ACCESS_TOKEN_ALG, JWT_ISSUER
)
from .store_sqlite import (
    init_sqlite, insert_event, insert_refresh_token,
    revoke_refresh_token, insert_token_event, get_latest_revocation_ts
)
from .pqc_crypto import canonical_bytes, dilithium_sign, generate_kyber_keypair
from .kafka_pub import start_producer, publish_event, publish_token_event
from .jwt_utils import get_token_claims, is_token_revoked
from .p1_client import p1_signer_client
from .refresh_token_utils import (
    create_refresh_token, perform_kyber_refresh,
    get_refresh_token_claims
)
from .models import (
    RevokeRequest,
    RevokeResponse,
    RevokeTokenRequest,
    RevokeTokenResponse,
    RevocationStatusResponse,
    RevocationCheckRequest,
    RevocationCheckResponse,
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


def _decode_unverified_claims(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload_segment = parts[1]
        payload_segment += "=" * (-len(payload_segment) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_segment.encode("ascii"))
        claims = json.loads(payload_bytes.decode("utf-8"))
        return claims if isinstance(claims, dict) else {}
    except Exception:
        return {}


def _decode_unverified_header(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        header_segment = parts[0]
        header_segment += "=" * (-len(header_segment) % 4)
        header_bytes = base64.urlsafe_b64decode(header_segment.encode("ascii"))
        header = json.loads(header_bytes.decode("utf-8"))
        return header if isinstance(header, dict) else {}
    except Exception:
        return {}


async def _publish_revocation_event(
    rev_type: str,
    value: str,
    ttl_seconds: Optional[int] = None,
) -> str:
    global rds, producer
    if not rds or not producer:
        raise HTTPException(status_code=503, detail="Service not ready")

    event_id = str(uuid.uuid4())
    nonce = secrets.token_urlsafe(16)
    ts = utc_now_iso()

    unsigned = {
        "event_id": event_id,
        "type": rev_type,
        "value": value,
        "ts": ts,
        "nonce": nonce,
        "kid": PQC_SIGNING_KEY_ID,
    }
    sig = dilithium_sign(canonical_bytes(unsigned))

    event = dict(unsigned)
    event["sig"] = sig

    insert_event(event)

    keyspace = rev_type.split("_")[1]  # jti/sub/kid
    redis_key = f"revoked:{keyspace}:{value}"
    if ttl_seconds:
        await rds.setex(redis_key, ttl_seconds, "1")
    else:
        await rds.set(redis_key, "1")

    await publish_event(producer, canonical_bytes(event))
    return event_id


async def issue_access_token(
    subject: str,
    expires_minutes: Optional[int] = None,
    additional_claims: Optional[dict] = None
) -> tuple[str, dict]:
    now = datetime.now(timezone.utc)
    expiry_minutes = expires_minutes or JWT_ACCESS_TOKEN_EXPIRE_MINUTES
    exp_ts = int((now + timedelta(minutes=expiry_minutes)).timestamp())
    iat_ts = int(now.timestamp())

    claims = {
        "sub": subject,
        "exp": exp_ts,
        "iat": iat_ts,
        "iss": JWT_ISSUER,
        "type": "access",
    }
    if additional_claims:
        claims.update(additional_claims)

    if ACCESS_TOKEN_PROVIDER != "p1":
        raise HTTPException(
            status_code=500,
            detail="Unsupported ACCESS_TOKEN_PROVIDER; only 'p1' is allowed in PQ mode",
        )

    token = await p1_signer_client.sign_access_token(claims=claims, alg=P1_ACCESS_TOKEN_ALG)
    decoded = _decode_unverified_claims(token)
    if not decoded:
        raise HTTPException(status_code=502, detail="P1 returned malformed JWT payload")
    return token, decoded


async def validate_access_token_provider_aware(
    token: str,
    check_revocation: bool,
) -> dict:
    """
    Validate access token according to configured provider mode.
    - local: P4 local JWT validation
    - p1: signature validation delegated to P1 /verify, then claims checks in P4
    """
    global rds

    if ACCESS_TOKEN_PROVIDER != "p1":
        raise HTTPException(
            status_code=500,
            detail="Unsupported ACCESS_TOKEN_PROVIDER; only 'p1' is allowed in PQ mode",
        )

    claims = _decode_unverified_claims(token)
    if not claims:
        raise HTTPException(status_code=401, detail="Invalid token format")

    header = _decode_unverified_header(token)
    claims_for_revocation = dict(claims)
    kid = header.get("kid")
    if isinstance(kid, str) and kid:
        claims_for_revocation["kid"] = kid

    if check_revocation:
        is_revoked, reason = await is_token_revoked(claims_for_revocation, rds)
        if is_revoked:
            if reason == "sub":
                detail = "Token has been revoked (all tokens for this subject are revoked)"
            elif reason == "kid":
                detail = "Token has been revoked (all tokens for this key are revoked)"
            else:
                detail = "Token has been revoked"
            raise HTTPException(status_code=401, detail=detail)

    verify_result = await p1_signer_client.verify_access_token(token)
    if not bool(verify_result.get("valid")):
        reason = verify_result.get("error") or verify_result.get("reason") or "signature_invalid"
        raise HTTPException(status_code=401, detail=f"Invalid token: {reason}")

    exp = claims.get("exp")
    now_ts = int(datetime.now(timezone.utc).timestamp())
    if not isinstance(exp, int):
        raise HTTPException(status_code=401, detail="Invalid token: missing or invalid exp")
    if exp < now_ts:
        raise HTTPException(status_code=401, detail="Token has expired")

    iss = claims.get("iss")
    if not isinstance(iss, str) or iss != JWT_ISSUER:
        raise HTTPException(status_code=401, detail="Invalid token issuer")

    return claims


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
    await p1_signer_client.close()


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


@app.get("/v1/revocations/{jti}", response_model=RevocationStatusResponse)
async def get_revocation_status(jti: str):
    """
    P3-compatible revocation lookup endpoint.
    Returns whether this token jti is currently revoked.
    """
    global rds
    if not rds:
        raise HTTPException(status_code=503, detail="Service not ready")

    revoked = await rds.get(f"revoked:jti:{jti}")
    if not revoked:
        return RevocationStatusResponse(jti=jti, revoked=False, revokedAt=None)

    revoked_at = get_latest_revocation_ts("revoke_jti", jti)
    return RevocationStatusResponse(jti=jti, revoked=True, revokedAt=revoked_at)


@app.post("/v1/revocations/check", response_model=RevocationCheckResponse)
async def check_revocation_status(req: RevocationCheckRequest):
    """
    Check revocation by any of jti/sub/kid.
    Returns revoked=true if any supplied identifier is revoked.
    """
    global rds
    if not rds:
        raise HTTPException(status_code=503, detail="Service not ready")

    if not req.jti and not req.sub and not req.kid:
        raise HTTPException(status_code=400, detail="At least one of jti/sub/kid is required")

    if req.jti and await rds.get(f"revoked:jti:{req.jti}"):
        return RevocationCheckResponse(
            revoked=True,
            reason="jti",
            revokedAt=get_latest_revocation_ts("revoke_jti", req.jti),
        )

    if req.sub and await rds.get(f"revoked:sub:{req.sub}"):
        return RevocationCheckResponse(
            revoked=True,
            reason="sub",
            revokedAt=get_latest_revocation_ts("revoke_sub", req.sub),
        )

    if req.kid and await rds.get(f"revoked:kid:{req.kid}"):
        return RevocationCheckResponse(
            revoked=True,
            reason="kid",
            revokedAt=get_latest_revocation_ts("revoke_kid", req.kid),
        )

    return RevocationCheckResponse(revoked=False)


@app.post("/revoke", response_model=RevokeResponse)
async def revoke(req: RevokeRequest):
    event_id = await _publish_revocation_event(req.type, req.value, req.ttl_seconds)
    return RevokeResponse(event_id=event_id, published=True)


@app.post("/revoke/token", response_model=RevokeTokenResponse)
async def revoke_from_verified_token(req: RevokeTokenRequest):
    """
    Verify token with P1, then revoke by selected identifiers from verified token:
    - jti from claims
    - sub from claims
    - kid from JOSE header (via P1 verify response)
    """
    verify_result = await p1_signer_client.verify_access_token(req.token)
    if not bool(verify_result.get("valid")):
        reason = verify_result.get("error") or verify_result.get("reason") or "signature_invalid"
        raise HTTPException(status_code=401, detail=f"Token verification failed: {reason}")

    claims = verify_result.get("claims")
    if not isinstance(claims, dict):
        raise HTTPException(status_code=400, detail="Verified token missing claims")

    kid = verify_result.get("kid")
    if not isinstance(kid, str) or not kid:
        kid = None

    lookup = {
        "jti": claims.get("jti") if isinstance(claims.get("jti"), str) and claims.get("jti") else None,
        "sub": claims.get("sub") if isinstance(claims.get("sub"), str) and claims.get("sub") else None,
        "kid": kid,
    }

    if not req.scopes:
        raise HTTPException(status_code=400, detail="At least one scope is required")

    event_ids: list[str] = []
    revoked: dict[str, str] = {}
    for scope in req.scopes:
        value = lookup.get(scope)
        if not value:
            raise HTTPException(status_code=400, detail=f"Token missing required value for scope: {scope}")
        rev_type = f"revoke_{scope}"
        event_id = await _publish_revocation_event(rev_type, value, req.ttl_seconds)
        event_ids.append(event_id)
        revoked[scope] = value

    return RevokeTokenResponse(revoked=revoked, event_ids=event_ids, published=True)


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
    
    token, claims = await issue_access_token(
        subject=req.subject,
        expires_minutes=req.expires_minutes,
        additional_claims=req.additional_claims,
    )

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
        # Validate the token (signature, expiration, issuer, revocation)
        payload = await validate_access_token_provider_aware(
            token=req.token,
            check_revocation=req.check_revocation,
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
                claims_for_revocation = dict(claims)
                header = _decode_unverified_header(req.token)
                kid = header.get("kid")
                if isinstance(kid, str) and kid:
                    claims_for_revocation["kid"] = kid
                is_revoked, revocation_reason = await is_token_revoked(claims_for_revocation, rds)
            
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
            claims_for_revocation = dict(claims)
            header = _decode_unverified_header(token)
            kid = header.get("kid")
            if isinstance(kid, str) and kid:
                claims_for_revocation["kid"] = kid
            is_revoked, revocation_reason = await is_token_revoked(claims_for_revocation, rds)
        
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
    
    Returns both access token and refresh token for Kyber-forward-secure refresh.
    """
    global rds, producer
    if not rds or not producer:
        raise HTTPException(status_code=503, detail="Service not ready")
    
    event_id = str(uuid.uuid4())
    ts = utc_now_iso()
    
    # Create refresh token with client binding
    refresh_token, client_hash = create_refresh_token(
        subject=req.subject,
        client_binding=req.client_binding,
        additional_claims=req.additional_claims
    )
    
    # Get refresh token claims
    refresh_claims = get_refresh_token_claims(refresh_token)
    refresh_jti = refresh_claims.get("jti")
    refresh_exp = refresh_claims.get("exp")
    
    if not refresh_jti:
        raise HTTPException(status_code=500, detail="Failed to create refresh token")

    # Create access token (local or via P1 based on configuration)
    access_additional_claims = dict(req.additional_claims or {})
    access_additional_claims["refresh_jti"] = refresh_jti
    access_token, access_claims = await issue_access_token(
        subject=req.subject,
        additional_claims=access_additional_claims,
    )
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
            kyber_public_key=None,
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
            "client_hash": client_hash
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
    
    client_public_key, _ = generate_kyber_keypair()

    return RefreshTokenResponse(
        refresh_token=refresh_token,
        access_token=access_token,
        token_type="bearer",
        expires_in=access_expires_in,
        refresh_expires_in=refresh_expires_in,
        refresh_jti=refresh_jti,
        access_jti=access_jti,
        subject=req.subject,
        client_public_key=client_public_key
    )


@app.post("/token/refresh", response_model=RefreshTokenRefreshResponse)
async def refresh_token_endpoint(req: RefreshTokenRefreshRequest):
    """
    Refresh access token using refresh token with Kyber forward secrecy.
    
    - **refresh_token**: The refresh token
    - **client_binding**: Current client identifier (must match original)
    - **client_public_key**: Client's Kyber KEM public key for forward secrecy
    
    Returns new access token, rotated refresh token, and Kyber KEM ciphertext.
    """
    global rds, producer
    if not rds or not producer:
        raise HTTPException(status_code=503, detail="Service not ready")
    
    event_id = str(uuid.uuid4())
    ts = utc_now_iso()

    # Perform Kyber-based refresh
    try:
        _, kem_ciphertext, encrypted_session_key = await perform_kyber_refresh(
            refresh_token=req.refresh_token,
            client_binding=req.client_binding,
            client_public_key=req.client_public_key,
            redis_client=rds
        )
    except HTTPException:
        raise

    # Validate current refresh token identity before rotating
    refresh_claims = get_refresh_token_claims(req.refresh_token)
    old_refresh_jti = refresh_claims.get("jti")
    subject = refresh_claims.get("sub")
    if not old_refresh_jti or not subject:
        raise HTTPException(status_code=400, detail="Invalid refresh token claims")

    # Rotate refresh token: issue a brand-new one bound to the same client binding
    new_refresh_token, client_hash = create_refresh_token(
        subject=subject,
        client_binding=req.client_binding,
    )
    new_refresh_claims = get_refresh_token_claims(new_refresh_token)
    new_refresh_jti = new_refresh_claims.get("jti")
    new_refresh_exp = new_refresh_claims.get("exp")
    if not new_refresh_jti:
        raise HTTPException(status_code=500, detail="Failed to rotate refresh token")

    # Create new access token linked to the new refresh token
    access_token, access_claims = await issue_access_token(
        subject=subject,
        additional_claims={"refresh_jti": new_refresh_jti, "prev_refresh_jti": old_refresh_jti}
    )
    access_jti = access_claims.get("jti")
    access_exp = access_claims.get("exp")

    # Calculate expiration windows
    if access_exp:
        expires_in = int(access_exp - datetime.now(timezone.utc).timestamp())
    else:
        expires_in = JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60

    if new_refresh_exp:
        refresh_expires_in = int(new_refresh_exp - datetime.now(timezone.utc).timestamp())
        new_refresh_expires_at = datetime.fromtimestamp(new_refresh_exp, tz=timezone.utc).isoformat()
    else:
        refresh_expires_in = JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
        new_refresh_expires_at = (
            datetime.now(timezone.utc) + timedelta(days=JWT_REFRESH_TOKEN_EXPIRE_DAYS)
        ).isoformat()

    # Revoke previous refresh token in audit + cache
    revoke_refresh_token(old_refresh_jti, ts)
    await rds.set(f"revoked:jti:{old_refresh_jti}", "1")
    await rds.delete(f"refresh_token:{old_refresh_jti}")

    # Persist and cache rotated refresh token
    insert_refresh_token(
        token_id=new_refresh_jti,
        subject=subject,
        client_hash=client_hash,
        kyber_public_key=req.client_public_key,
        created_at=ts,
        expires_at=new_refresh_expires_at,
    )
    await rds.setex(
        f"refresh_token:{new_refresh_jti}",
        refresh_expires_in,
        json.dumps({
            "subject": subject,
            "client_hash": client_hash,
            "rotated_from": old_refresh_jti,
            "last_used": ts,
        })
    )

    # Publish a formal revocation event for old refresh token
    revoke_event_id = str(uuid.uuid4())
    revoke_unsigned = {
        "event_id": revoke_event_id,
        "type": "revoke_jti",
        "value": old_refresh_jti,
        "ts": ts,
        "nonce": secrets.token_urlsafe(16),
        "kid": PQC_SIGNING_KEY_ID,
    }
    revoke_sig = dilithium_sign(canonical_bytes(revoke_unsigned))
    revoke_event = dict(revoke_unsigned)
    revoke_event["sig"] = revoke_sig
    insert_event(revoke_event)
    await publish_event(producer, canonical_bytes(revoke_event))

    # Publish token rotation event to Kafka
    refresh_event = {
        "event_id": event_id,
        "event_type": "refresh_token_rotated",
        "token_id": old_refresh_jti,
        "new_token_id": new_refresh_jti,
        "subject": subject,
        "client_hash": client_hash,
        "new_access_jti": access_jti,
        "ts": ts,
        "nonce": secrets.token_urlsafe(16),
        "kid": PQC_SIGNING_KEY_ID,
    }
    refresh_event["sig"] = dilithium_sign(canonical_bytes(refresh_event))

    # Audit log
    insert_token_event(
        event_id=event_id,
        event_type="refresh_token_rotated",
        token_id=old_refresh_jti,
        subject=subject,
        ts=ts,
        data=json.dumps({
            "new_token_id": new_refresh_jti,
            "new_access_jti": access_jti,
        }),
        published=True
    )

    # Publish to Kafka
    await publish_token_event(producer, canonical_bytes(refresh_event))

    return RefreshTokenRefreshResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        refresh_jti=new_refresh_jti,
        refresh_expires_in=refresh_expires_in,
        token_type="bearer",
        expires_in=expires_in,
        kem_ciphertext=kem_ciphertext,
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
