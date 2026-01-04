import os

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:29092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "revocations")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
SQLITE_PATH = os.getenv("SQLITE_PATH", "./revocation.db")

PQC_SIGNING_KEY_ID = os.getenv("PQC_SIGNING_KEY_ID", "p4-dilithium-key-1")
KYBER_KEM_ALG = os.getenv("KYBER_KEM_ALG", "ML-KEM-512")

NONCE_TTL_SECONDS = int(os.getenv("NONCE_TTL_SECONDS", "180"))

# JWT Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
JWT_ISSUER = os.getenv("JWT_ISSUER", "p4-revocation-service")

# Refresh Token Configuration
JWT_REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "90"))
REFRESH_TOKEN_TOPIC = os.getenv("REFRESH_TOKEN_TOPIC", "token-events")
