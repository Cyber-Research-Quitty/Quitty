# Implementation Guide - JWT Token System with Kyber Forward Secrecy

This guide will walk you through setting up and running the complete JWT token system with refresh tokens, client binding, and Kyber-based forward secrecy.

## Prerequisites

- Python 3.8 or higher
- Docker and Docker Compose (for Redis and Kafka)
- Or install Redis and Kafka manually

## Step 1: Setup Environment

### 1.1 Create Virtual Environment

```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux/Mac
python3 -m venv .venv
source .venv/bin/activate
```

### 1.2 Install Dependencies

```bash
pip install -r requirements.txt
```

## Step 2: Start Infrastructure Services

### Option A: Using Docker Compose (Recommended)

```bash
# Start Redis and Kafka
docker-compose up -d

# Verify services are running
docker ps
```

You should see:
- `p4-redis` on port 6379
- `p4-zookeeper` on port 2181
- `p4-kafka` on port 29092

### Option B: Manual Installation

**Redis:**
```bash
# Windows: Download from https://redis.io/download
# Linux: sudo apt-get install redis-server
# Mac: brew install redis

redis-server
```

**Kafka:**
```bash
# Download from https://kafka.apache.org/downloads
# Follow Kafka quickstart guide
```

## Step 3: Configure Environment Variables (Optional)

**Note**: This step is optional! The application will work with default values. However, you should configure at least `JWT_SECRET_KEY` for production use.

Create a `.env` file in the project root (optional, defaults are provided):

```env
# Kafka Configuration
KAFKA_BOOTSTRAP=localhost:29092
KAFKA_TOPIC=revocations
REFRESH_TOKEN_TOPIC=token-events

# Redis Configuration
REDIS_URL=redis://localhost:6379/0

# SQLite Configuration
SQLITE_PATH=./revocation.db

# JWT Configuration
JWT_SECRET_KEY=your-very-secure-secret-key-change-this-in-production
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=90
JWT_ISSUER=p4-revocation-service

# PQC Configuration
PQC_SIGNING_KEY_ID=p4-dilithium-key-1
NONCE_TTL_SECONDS=180
```

**Default Values (if you skip this step):**
- `JWT_SECRET_KEY`: `"your-secret-key-change-in-production"` ⚠️ **Change this in production!**
- `JWT_ACCESS_TOKEN_EXPIRE_MINUTES`: `30`
- `JWT_REFRESH_TOKEN_EXPIRE_DAYS`: `90`
- `KAFKA_BOOTSTRAP`: `"localhost:29092"`
- `REDIS_URL`: `"redis://localhost:6379/0"`
- `SQLITE_PATH`: `"./revocation.db"`

**When to configure:**
- ✅ **Production**: Always configure `JWT_SECRET_KEY` with a strong random key
- ✅ **Custom ports**: If Redis/Kafka run on different ports
- ✅ **Custom expiration**: If you want different token lifetimes
- ❌ **Development/Testing**: You can skip this and use defaults

## Step 4: Initialize Database

The SQLite database will be automatically created when you start the application. The schema includes:
- `revocation_events` - Revocation audit log
- `refresh_tokens` - Refresh token records
- `token_events` - Token operation audit log

## Step 5: Run the Application

### 5.1 Start the Main API Server

```bash
# From project root
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at: `http://localhost:8000`

### 5.2 Start the Kafka Consumer (in a separate terminal)

```bash
# Activate virtual environment first
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/Mac

# Run consumer
python -m consumer.consumer
```

The consumer will:
- Listen to revocation events
- Listen to token events
- Update Redis cache automatically

## Step 6: Access API Documentation

Open your browser and navigate to:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## Step 7: Testing the API

### 7.1 Health Check

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{"ok": true}
```

### 7.2 Create Access Token

```bash
curl -X POST "http://localhost:8000/token" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "user123",
    "expires_minutes": 60,
    "additional_claims": {"role": "admin"}
  }'
```

Response:
```json
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 3600,
  "jti": "uuid-here",
  "subject": "user123"
}
```

### 7.3 Validate Token

```bash
curl -X POST "http://localhost:8000/token/validate" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "YOUR_ACCESS_TOKEN_HERE",
    "check_revocation": true
  }'
```

### 7.4 Create Refresh Token (with Client Binding)

```bash
curl -X POST "http://localhost:8000/token/refresh/create" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "user123",
    "client_binding": "device-fingerprint-abc123",
    "additional_claims": {"role": "admin"}
  }'
```

Response:
```json
{
  "refresh_token": "eyJ...",
  "access_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 1800,
  "refresh_expires_in": 7776000,
  "refresh_jti": "uuid-here",
  "access_jti": "uuid-here",
  "subject": "user123",
  "kyber_public_key": "base64-encoded-key"
}
```

**Important**: Save the `refresh_token` and `kyber_public_key` for the next step.

### 7.5 Refresh Access Token (with Kyber Forward Secrecy)

First, generate a client Kyber key pair (you'll need to implement this on the client side, or use the server's public key):

```bash
# For testing, you can use the server's public key
# In production, the client should generate its own key pair

curl -X POST "http://localhost:8000/token/refresh" \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "YOUR_REFRESH_TOKEN_HERE",
    "client_binding": "device-fingerprint-abc123",
    "client_public_key": "YOUR_CLIENT_PUBLIC_KEY_BASE64"
  }'
```

Response:
```json
{
  "access_token": "eyJ...",
  "refresh_token": null,
  "token_type": "bearer",
  "expires_in": 1800,
  "server_public_key": "base64-encoded-key",
  "encrypted_session_key": "encrypted-key",
  "access_jti": "uuid-here"
}
```

### 7.6 Revoke Token

```bash
# Revoke by JTI
curl -X POST "http://localhost:8000/revoke" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "revoke_jti",
    "value": "token-jti-here",
    "ttl_seconds": 3600
  }'

# Revoke refresh token
curl -X POST "http://localhost:8000/token/refresh/revoke" \
  -H "Content-Type: application/json" \
  -d '"YOUR_REFRESH_TOKEN_HERE"'
```

## Step 8: Client Implementation Example

### Python Client Example

```python
import requests
import base64
from app.pqc_crypto import KyberKeyExchange

# Base URL
BASE_URL = "http://localhost:8000"

# 1. Create refresh token
def create_refresh_token(subject: str, device_fingerprint: str):
    response = requests.post(
        f"{BASE_URL}/token/refresh/create",
        json={
            "subject": subject,
            "client_binding": device_fingerprint
        }
    )
    return response.json()

# 2. Refresh access token with Kyber
def refresh_access_token(refresh_token: str, client_binding: str):
    # Generate client key pair
    private_key, public_key = KyberKeyExchange.generate_keypair()
    public_key_encoded = KyberKeyExchange.encode_public_key(public_key)
    
    response = requests.post(
        f"{BASE_URL}/token/refresh",
        json={
            "refresh_token": refresh_token,
            "client_binding": client_binding,
            "client_public_key": public_key_encoded
        }
    )
    
    if response.status_code == 200:
        data = response.json()
        # Derive shared secret with server's public key
        server_public_key = data["server_public_key"]
        shared_secret = KyberKeyExchange.derive_shared_secret(
            private_key,
            KyberKeyExchange.decode_public_key(server_public_key)
        )
        return data, shared_secret
    
    return None, None

# Usage
if __name__ == "__main__":
    # Create tokens
    tokens = create_refresh_token("user123", "device-abc123")
    print(f"Access Token: {tokens['access_token']}")
    print(f"Refresh Token: {tokens['refresh_token']}")
    
    # Refresh token
    new_tokens, secret = refresh_access_token(
        tokens["refresh_token"],
        "device-abc123"
    )
    print(f"New Access Token: {new_tokens['access_token']}")
```

## Step 9: Verify Everything is Working

### Check Redis Cache

```bash
# Connect to Redis
redis-cli

# Check revoked tokens
KEYS revoked:*

# Check refresh tokens
KEYS refresh_token:*

# Get a specific token
GET refresh_token:YOUR_TOKEN_ID
```

### Check SQLite Database

```bash
# Using sqlite3 command line
sqlite3 revocation.db

# View refresh tokens
SELECT * FROM refresh_tokens;

# View token events
SELECT * FROM token_events ORDER BY ts DESC LIMIT 10;

# View revocation events
SELECT * FROM revocation_events ORDER BY ts DESC LIMIT 10;
```

### Check Kafka Topics

```bash
# List topics
docker exec -it p4-kafka kafka-topics --list --bootstrap-server localhost:29092

# Consume messages from a topic
docker exec -it p4-kafka kafka-console-consumer \
  --bootstrap-server localhost:29092 \
  --topic revocations \
  --from-beginning

docker exec -it p4-kafka kafka-console-consumer \
  --bootstrap-server localhost:29092 \
  --topic token-events \
  --from-beginning
```

## Troubleshooting

### Issue: Redis Connection Error
**Solution**: Make sure Redis is running
```bash
docker-compose up -d redis
# or
redis-server
```

### Issue: Kafka Connection Error
**Solution**: Make sure Kafka and Zookeeper are running
```bash
docker-compose up -d
# Wait a few seconds for services to start
```

### Issue: Database Locked
**Solution**: SQLite database might be locked. Make sure only one process is accessing it.

### Issue: Token Validation Fails
**Solution**: 
- Check if token is expired
- Verify JWT_SECRET_KEY matches
- Check if token is revoked in Redis

### Issue: Client Binding Mismatch
**Solution**: Make sure you're using the same `client_binding` value that was used when creating the refresh token.

## Production Considerations

1. **Change JWT_SECRET_KEY**: Use a strong, randomly generated secret key
2. **Use Environment Variables**: Don't hardcode secrets
3. **Enable HTTPS**: Always use HTTPS in production
4. **Rate Limiting**: Add rate limiting to prevent abuse
5. **Monitoring**: Set up logging and monitoring
6. **Backup SQLite**: Regularly backup the SQLite database
7. **Redis Persistence**: Configure Redis persistence (AOF or RDB)
8. **Kafka Replication**: Configure Kafka with replication factor > 1

## Next Steps

- Implement actual Kyber algorithm (currently using X25519 as placeholder)
- Add token rotation for refresh tokens
- Implement refresh token family tracking
- Add rate limiting
- Set up monitoring and alerting
- Configure production-grade logging

## API Endpoints Summary

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/token` | Create access token |
| POST | `/token/validate` | Validate token |
| GET | `/token/inspect` | Inspect token claims |
| POST | `/token/refresh/create` | Create refresh token |
| POST | `/token/refresh` | Refresh access token |
| POST | `/token/refresh/revoke` | Revoke refresh token |
| POST | `/revoke` | Revoke token by JTI/sub/KID |

For detailed API documentation, visit: http://localhost:8000/docs


