# app/main.py
import uuid
import secrets
from datetime import datetime, timezone
from typing import Optional

import redis.asyncio as redis
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .config import REDIS_URL, PQC_SIGNING_KEY_ID
from .store_sqlite import init_sqlite, insert_event
from .pqc_crypto import canonical_bytes, dilithium_sign
from .kafka_pub import start_producer, publish_event

app = FastAPI(title="P4 Enhanced Secure Revocation (SQLite)", version="1.0")

# Runtime handles
rds: Optional[redis.Redis] = None
producer = None


# -------------------------
# Models (kept inside main.py to avoid import confusion)
# -------------------------
class RevokeRequest(BaseModel):
    type: str = Field(..., pattern=r"^(revoke_jti|revoke_sub|revoke_kid)$")
    value: str = Field(..., min_length=1, max_length=512)
    ttl_seconds: Optional[int] = Field(None, ge=30, le=60 * 60 * 24 * 30)


class RevokeResponse(BaseModel):
    event_id: str
    published: bool


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
