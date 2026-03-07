import asyncio
import logging
import os

from aiokafka import AIOKafkaProducer
from .config import KAFKA_BOOTSTRAP, KAFKA_TOPIC, REFRESH_TOKEN_TOPIC

logger = logging.getLogger(__name__)

async def start_producer() -> AIOKafkaProducer:
    retries = int(os.getenv("KAFKA_CONNECT_RETRIES", "20"))
    retry_delay = float(os.getenv("KAFKA_CONNECT_RETRY_DELAY_SECONDS", "1.5"))
    last_error = None

    for attempt in range(1, retries + 1):
        producer = AIOKafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP)
        try:
            await producer.start()
            if attempt > 1:
                logger.info(
                    "Kafka producer connected on attempt %s/%s",
                    attempt,
                    retries,
                )
            return producer
        except Exception as exc:
            last_error = exc
            try:
                await producer.stop()
            except Exception:
                pass

            if attempt < retries:
                logger.warning(
                    "Kafka not ready (%s/%s): %s. Retrying in %.1fs",
                    attempt,
                    retries,
                    exc,
                    retry_delay,
                )
                await asyncio.sleep(retry_delay)

    raise RuntimeError(
        f"Unable to connect to Kafka at {KAFKA_BOOTSTRAP} after {retries} attempts"
    ) from last_error

async def publish_event(producer: AIOKafkaProducer, payload: bytes) -> None:
    """Publish revocation event to Kafka"""
    await producer.send_and_wait(KAFKA_TOPIC, payload)

async def publish_token_event(producer: AIOKafkaProducer, payload: bytes) -> None:
    """Publish token event (refresh token operations) to Kafka"""
    await producer.send_and_wait(REFRESH_TOKEN_TOPIC, payload)
