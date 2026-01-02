import os

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "revocations")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
SQLITE_PATH = os.getenv("SQLITE_PATH", "./revocation.db")

PQC_SIGNING_KEY_ID = os.getenv("PQC_SIGNING_KEY_ID", "p4-dilithium-key-1")

NONCE_TTL_SECONDS = int(os.getenv("NONCE_TTL_SECONDS", "180"))
