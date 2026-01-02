import json, asyncio
import redis.asyncio as redis
from aiokafka import AIOKafkaConsumer

from app.config import (
    KAFKA_BOOTSTRAP, KAFKA_TOPIC, REDIS_URL, NONCE_TTL_SECONDS,
    REFRESH_TOKEN_TOPIC
)
from app.pqc_crypto import canonical_bytes, dilithium_verify

async def process_revocation_event(event: dict, rds: redis.Redis):
    """Process revocation event"""
    sig = event.get("sig", "")
    kid = event.get("kid", "")
    nonce = event.get("nonce", "")

    # replay protection
    nonce_key = f"seen:rev_nonce:{nonce}"
    if await rds.get(nonce_key):
        return
    await rds.setex(nonce_key, NONCE_TTL_SECONDS, "1")

    unsigned = dict(event)
    unsigned.pop("sig", None)

    if not dilithium_verify(canonical_bytes(unsigned), sig, kid):
        return

    rtype = event["type"]          # revoke_jti/sub/kid
    value = event["value"]
    keyspace = rtype.split("_")[1] # jti/sub/kid
    await rds.set(f"revoked:{keyspace}:{value}", "1")


async def process_token_event(event: dict, rds: redis.Redis):
    """Process token event (refresh token operations)"""
    sig = event.get("sig", "")
    kid = event.get("kid", "")
    nonce = event.get("nonce", "")
    event_type = event.get("event_type", "")

    # replay protection
    nonce_key = f"seen:token_nonce:{nonce}"
    if await rds.get(nonce_key):
        return
    await rds.setex(nonce_key, NONCE_TTL_SECONDS, "1")

    unsigned = dict(event)
    unsigned.pop("sig", None)

    if not dilithium_verify(canonical_bytes(unsigned), sig, kid):
        return

    # Handle different token event types
    if event_type == "refresh_token_created":
        token_id = event.get("token_id")
        subject = event.get("subject")
        client_hash = event.get("client_hash")
        kyber_pub = event.get("kyber_pub")
        
        if token_id:
            # Cache refresh token metadata
            await rds.setex(
                f"refresh_token:{token_id}",
                90 * 24 * 60 * 60,  # 90 days
                json.dumps({
                    "subject": subject,
                    "client_hash": client_hash,
                    "kyber_pub": kyber_pub,
                    "created": True
                })
            )
    
    elif event_type == "token_refreshed":
        token_id = event.get("token_id")
        new_access_jti = event.get("new_access_jti")
        
        if token_id:
            # Update last used timestamp in cache
            cached = await rds.get(f"refresh_token:{token_id}")
            if cached:
                data = json.loads(cached)
                data["last_used"] = event.get("ts")
                data["last_access_jti"] = new_access_jti
                await rds.setex(
                    f"refresh_token:{token_id}",
                    90 * 24 * 60 * 60,
                    json.dumps(data)
                )
    
    elif event_type == "refresh_token_revoked":
        token_id = event.get("token_id")
        
        if token_id:
            # Mark as revoked in cache
            await rds.set(f"revoked:jti:{token_id}", "1")
            await rds.delete(f"refresh_token:{token_id}")


async def run():
    rds = redis.from_url(REDIS_URL, decode_responses=True)
    
    # Subscribe to both revocation and token event topics
    consumer = AIOKafkaConsumer(
        KAFKA_TOPIC,
        REFRESH_TOKEN_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        group_id="revocation-consumers"
    )

    await consumer.start()
    try:
        async for msg in consumer:
            try:
                event = json.loads(msg.value.decode("utf-8"))
                
                # Route to appropriate handler based on topic
                if msg.topic == KAFKA_TOPIC:
                    await process_revocation_event(event, rds)
                elif msg.topic == REFRESH_TOKEN_TOPIC:
                    await process_token_event(event, rds)
            except Exception as e:
                # Log error but continue processing
                print(f"Error processing event: {e}")
                continue
    finally:
        await consumer.stop()
        await rds.close()

if __name__ == "__main__":
    asyncio.run(run())
