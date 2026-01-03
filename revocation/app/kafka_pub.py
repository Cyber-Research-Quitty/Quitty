from aiokafka import AIOKafkaProducer
from .config import KAFKA_BOOTSTRAP, KAFKA_TOPIC, REFRESH_TOKEN_TOPIC

async def start_producer() -> AIOKafkaProducer:
    producer = AIOKafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP)
    await producer.start()
    return producer

async def publish_event(producer: AIOKafkaProducer, payload: bytes) -> None:
    """Publish revocation event to Kafka"""
    await producer.send_and_wait(KAFKA_TOPIC, payload)

async def publish_token_event(producer: AIOKafkaProducer, payload: bytes) -> None:
    """Publish token event (refresh token operations) to Kafka"""
    await producer.send_and_wait(REFRESH_TOKEN_TOPIC, payload)
