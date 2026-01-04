import json, asyncio
import sys
import os
import logging
from pathlib import Path

# Add parent directory to path so we can import app module
# This allows the script to be run from any directory
script_dir = Path(__file__).parent.absolute()
project_root = script_dir.parent

# Add project root to Python path
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Change to project root directory for consistent behavior
os.chdir(project_root)

logger = logging.getLogger("revocation.consumer")

def setup_logging():
    log_level = os.getenv("CONSUMER_LOG_LEVEL", "INFO").upper()
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s"
        )
    logger.setLevel(log_level)

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
        logger.debug("Skipping revocation event due to replay nonce=%s", nonce)
        return
    await rds.setex(nonce_key, NONCE_TTL_SECONDS, "1")

    unsigned = dict(event)
    unsigned.pop("sig", None)

    if not dilithium_verify(canonical_bytes(unsigned), sig, kid):
        logger.warning("Invalid revocation signature event_id=%s kid=%s", event.get("event_id"), kid)
        return

    rtype = event["type"]          # revoke_jti/sub/kid
    value = event["value"]
    keyspace = rtype.split("_")[1] # jti/sub/kid
    await rds.set(f"revoked:{keyspace}:{value}", "1")

    logger.info("Revocation cached: %s=%s", keyspace, value)


async def process_token_event(event: dict, rds: redis.Redis):
    """Process token event (refresh token operations)"""
    sig = event.get("sig", "")
    kid = event.get("kid", "")
    nonce = event.get("nonce", "")
    event_type = event.get("event_type", "")

    # replay protection
    nonce_key = f"seen:token_nonce:{nonce}"
    if await rds.get(nonce_key):
        logger.debug("Skipping token event due to replay nonce=%s", nonce)
        return
    await rds.setex(nonce_key, NONCE_TTL_SECONDS, "1")

    unsigned = dict(event)
    unsigned.pop("sig", None)

    if not dilithium_verify(canonical_bytes(unsigned), sig, kid):
        logger.warning("Invalid token signature event_id=%s kid=%s", event.get("event_id"), kid)
        return

    # Handle different token event types
    if event_type == "refresh_token_created":
        token_id = event.get("token_id")
        subject = event.get("subject")
        client_hash = event.get("client_hash")
        
        if token_id:
            # Cache refresh token metadata
            await rds.setex(
                f"refresh_token:{token_id}",
                90 * 24 * 60 * 60,  # 90 days
                json.dumps({
                    "subject": subject,
                    "client_hash": client_hash,
                    "created": True
                })
            )
            logger.info("Refresh token cached: token_id=%s subject=%s", token_id, subject)
    
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
            logger.info("Refresh token used: token_id=%s new_access_jti=%s", token_id, new_access_jti)
    
    elif event_type == "refresh_token_revoked":
        token_id = event.get("token_id")
        
        if token_id:
            # Mark as revoked in cache
            await rds.set(f"revoked:jti:{token_id}", "1")
            await rds.delete(f"refresh_token:{token_id}")
            logger.info("Refresh token revoked: token_id=%s", token_id)
    else:
        logger.warning("Unknown token event_type=%s", event_type)


async def run():
    setup_logging()
    logger.info("Starting consumer")
    group_id = os.getenv("CONSUMER_GROUP_ID", "revocation-consumers")
    auto_offset_reset = os.getenv("CONSUMER_OFFSET_RESET", "latest")

    logger.info("Subscribing to topics: %s, %s", KAFKA_TOPIC, REFRESH_TOKEN_TOPIC)
    logger.info("Kafka bootstrap: %s", KAFKA_BOOTSTRAP)
    logger.info("Consumer group: %s", group_id)
    logger.info("Offset reset: %s", auto_offset_reset)

    rds = redis.from_url(REDIS_URL, decode_responses=True)
    
    # Subscribe to both revocation and token event topics
    consumer = AIOKafkaConsumer(
        KAFKA_TOPIC,
        REFRESH_TOKEN_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        group_id=group_id,
        auto_offset_reset=auto_offset_reset
    )

    await consumer.start()
    logger.info("Consumer started; waiting for messages")
    try:
        async for msg in consumer:
            try:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(
                        "Received message topic=%s partition=%s offset=%s",
                        msg.topic,
                        msg.partition,
                        msg.offset
                    )
                event = json.loads(msg.value.decode("utf-8"))
                
                # Route to appropriate handler based on topic
                if msg.topic == KAFKA_TOPIC:
                    await process_revocation_event(event, rds)
                elif msg.topic == REFRESH_TOKEN_TOPIC:
                    await process_token_event(event, rds)
            except Exception as e:
                # Log error but continue processing
                logger.exception("Error processing event on topic=%s", msg.topic)
                continue
    finally:
        await consumer.stop()
        await rds.close()

if __name__ == "__main__":
    asyncio.run(run())
