from aiokafka import AIOKafkaProducer
from .config import KAFKA_BOOTSTRAP, KAFKA_TOPIC

async def start_producer() -> AIOKafkaProducer:
    producer = AIOKafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP)
    await producer.start()
    return producer

async def publish_event(producer: AIOKafkaProducer, payload: bytes) -> None:
    await producer.send_and_wait(KAFKA_TOPIC, payload)
