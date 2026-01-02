import json, asyncio
import redis.asyncio as redis
from aiokafka import AIOKafkaConsumer

from app.config import KAFKA_BOOTSTRAP, KAFKA_TOPIC, REDIS_URL, NONCE_TTL_SECONDS
from app.pqc_crypto import canonical_bytes, dilithium_verify

async def run():
    rds = redis.from_url(REDIS_URL, decode_responses=True)
    consumer = AIOKafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        group_id="revocation-consumers"
    )

    await consumer.start()
    try:
        async for msg in consumer:
            event = json.loads(msg.value.decode("utf-8"))
            sig = event.get("sig", "")
            kid = event.get("kid", "")
            nonce = event.get("nonce", "")

            # replay protection
            nonce_key = f"seen:rev_nonce:{nonce}"
            if await rds.get(nonce_key):
                continue
            await rds.setex(nonce_key, NONCE_TTL_SECONDS, "1")

            unsigned = dict(event)
            unsigned.pop("sig", None)

            if not dilithium_verify(canonical_bytes(unsigned), sig, kid):
                continue

            rtype = event["type"]          # revoke_jti/sub/kid
            value = event["value"]
            keyspace = rtype.split("_")[1] # jti/sub/kid
            await rds.set(f"revoked:{keyspace}:{value}", "1")
    finally:
        await consumer.stop()
        await rds.close()

if __name__ == "__main__":
    asyncio.run(run())
