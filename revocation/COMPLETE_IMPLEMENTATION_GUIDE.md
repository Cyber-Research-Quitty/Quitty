# Complete Implementation Guide - JWT Token Revocation Service

This comprehensive guide covers everything you need to know to set up, configure, deploy, and use the JWT Token Revocation Service with Post-Quantum Cryptography, Redis caching, Kafka event streaming, and SQLite audit logging.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Installation & Setup](#installation--setup)
5. [Configuration](#configuration)
6. [Running the Service](#running-the-service)
7. [API Reference](#api-reference)
8. [Client Integration](#client-integration)
9. [Deployment](#deployment)
10. [Troubleshooting](#troubleshooting)
11. [Security Best Practices](#security-best-practices)

---

## Project Overview

### What This Service Does

This is a production-ready JWT token revocation and management service that provides:

- **JWT Token Generation & Validation**: Create and validate access tokens with configurable expiration
- **Token Revocation**: Revoke tokens by JTI (token ID), subject (user ID), or key ID
- **Refresh Tokens**: Long-lived refresh tokens with client device binding
- **Forward Secrecy**: Kyber-based (X25519) key exchange for post-quantum security
- **Event Streaming**: Kafka-based event propagation across microservices
- **Fast Lookups**: Redis caching for O(1) revocation checks
- **Audit Trail**: SQLite database for permanent audit logging

### Key Features

✅ **Dual Storage Pattern**: Redis for speed, SQLite for durability  
✅ **Event-Driven Architecture**: Kafka broadcasts revocation events  
✅ **Client Binding**: Refresh tokens bound to specific devices  
✅ **Revocation Priority**: Revoked tokens are rejected even if expired  
✅ **Post-Quantum Ready**: PQC signatures (currently mock, ready for real implementation)  
✅ **Comprehensive Validation**: Signature, expiration, issuer, and revocation checks

---

## Architecture

### System Components

```
┌─────────────────┐
│   Client App    │
└────────┬────────┘
         │
         │ HTTP/REST
         │
┌────────▼────────────────────────────────────────┐
│         FastAPI Server (Port 8000)              │
│  ┌──────────────────────────────────────────┐  │
│  │  /token            - Create tokens       │  │
│  │  /token/validate   - Validate tokens     │  │
│  │  /token/refresh/*  - Refresh token flow  │  │
│  │  /revoke           - Revoke tokens       │  │
│  └──────────────────────────────────────────┘  │
└────┬──────────────┬──────────────┬─────────────┘
     │              │              │
     │              │              │
┌────▼────┐   ┌────▼────┐   ┌────▼────┐
│  Redis  │   │  Kafka  │   │ SQLite  │
│ (Cache) │   │(Events) │   │ (Audit) │
└─────────┘   └────┬────┘   └─────────┘
                   │
            ┌──────▼──────┐
            │   Consumer  │
            │   Service   │
            └─────────────┘
```

### Data Flow

#### Token Revocation Flow:
```
1. Client sends POST /revoke
2. Server creates signed revocation event
3. Event stored in SQLite (permanent audit)
4. Redis updated (revoked:jti:{jti} = "1")
5. Event published to Kafka
6. Consumer services update their Redis
```

#### Token Validation Flow:
```
1. Client sends POST /token/validate
2. Server decodes token (without validation)
3. Checks Redis for revocation (jti → sub → kid)
4. If not revoked, validates signature & expiration
5. Returns validation result
```

---

## Prerequisites

### Required Software

- **Python 3.8+** (3.10+ recommended)
- **Docker & Docker Compose** (for infrastructure)
- **Git** (for cloning the repository)

### Optional (for manual setup)

- **Redis 7+** (if not using Docker)
- **Apache Kafka** (if not using Docker)
- **Zookeeper** (if not using Docker)

---

## Installation & Setup

### Step 1: Clone or Navigate to Project

```bash
cd /path/to/revocation
```

### Step 2: Create Virtual Environment

**Windows:**
```powershell
python -m venv .venv
.venv\Scripts\activate
```

**Linux/Mac:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- `fastapi` - Web framework
- `uvicorn` - ASGI server
- `pydantic` - Data validation
- `redis` - Redis client
- `aiokafka` - Kafka client
- `PyJWT` - JWT handling
- `cryptography` - Cryptographic operations

### Step 4: Start Infrastructure Services

**Using Docker Compose (Recommended):**

```bash
docker-compose up -d
```

This starts:
- **Redis** on port `6379`
- **Zookeeper** on port `2181`
- **Kafka** on port `29092`

**Verify services are running:**
```bash
docker ps
```

You should see three containers:
- `p4-redis`
- `p4-zookeeper`
- `p4-kafka`

### Step 5: Initialize Database

The SQLite database (`revocation.db`) is automatically created on first run with these tables:

- `revocation_events` - All revocation events
- `refresh_tokens` - Refresh token metadata
- `token_events` - Token operation events

**Manual initialization (optional):**
```bash
python -c "from app.store_sqlite import init_sqlite; init_sqlite()"
```

---

## Configuration

### Environment Variables

Create a `.env` file in the project root (optional):

```env
# ============================================
# Kafka Configuration
# ============================================
KAFKA_BOOTSTRAP=localhost:29092
KAFKA_TOPIC=revocations
REFRESH_TOKEN_TOPIC=token-events

# ============================================
# Redis Configuration
# ============================================
REDIS_URL=redis://localhost:6379/0

# ============================================
# Database Configuration
# ============================================
SQLITE_PATH=./revocation.db

# ============================================
# JWT Configuration
# ============================================
JWT_SECRET_KEY=your-very-secure-secret-key-change-this-in-production
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=90
JWT_ISSUER=p4-revocation-service

# ============================================
# PQC Configuration
# ============================================
PQC_SIGNING_KEY_ID=p4-dilithium-key-1
NONCE_TTL_SECONDS=180
```

### Default Values

If you don't set environment variables, the service uses these defaults:

| Variable | Default Value | Notes |
|----------|--------------|-------|
| `JWT_SECRET_KEY` | `"your-secret-key-change-in-production"` | ⚠️ **MUST change in production** |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Access token lifetime |
| `JWT_REFRESH_TOKEN_EXPIRE_DAYS` | `90` | Refresh token lifetime |
| `KAFKA_BOOTSTRAP` | `localhost:29092` | Kafka broker address |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL |
| `SQLITE_PATH` | `./revocation.db` | Database file path |

### Loading Environment Variables

**Option 1: Export before running**
```bash
export JWT_SECRET_KEY="your-secret-key"
export JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
uvicorn app.main:app --reload
```

**Option 2: Use .env file (requires python-dotenv)**
```bash
pip install python-dotenv
# Add to app/config.py: from dotenv import load_dotenv; load_dotenv()
```

**Option 3: Use startup scripts**
- `start.sh` (Linux/Mac)
- `start.bat` (Windows)

---

## Running the Service

### Method 1: Manual Start

**Terminal 1 - Start API Server:**
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2 - Start Kafka Consumer:**
```bash
# Run from project root directory (recommended)
cd /path/to/revocation
python -m consumer

# Alternative: Run the script directly
python consumer/consumer.py
```

### Method 2: Using Startup Scripts

**Windows:**
```powershell
.\start.bat
```

**Linux/Mac:**
```bash
chmod +x start.sh
./start.sh
```

### Method 3: Production Deployment

**Using Gunicorn (recommended for production):**
```bash
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

### Verify Service is Running

```bash
# Health check
curl http://localhost:8000/health

# Expected response:
# {"ok": true}

# API documentation
open http://localhost:8000/docs
```

---

## API Reference

### Base URL
```
http://localhost:8000
```

### Authentication
All endpoints return JWT tokens. Use `Authorization: Bearer <token>` header for authenticated requests (if implemented in your application).

---

### 1. Health Check

**GET** `/health`

Check if the service is running.

**Response:**
```json
{
  "ok": true
}
```

---

### 2. Create Access Token

**POST** `/token`

Generate a new JWT access token.

**Request Body:**
```json
{
  "subject": "user123",
  "expires_minutes": 30,
  "additional_claims": {
    "role": "admin",
    "department": "IT"
  }
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800,
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "subject": "user123"
}
```

**Example:**
```bash
curl -X POST http://localhost:8000/token \
  -H "Content-Type: application/json" \
  -d '{"subject": "user123"}'
```

---

### 3. Validate Token

**POST** `/token/validate`

Validate a JWT token (signature, expiration, revocation).

**Request Body:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "check_revocation": true
}
```

**Response (Valid Token):**
```json
{
  "valid": true,
  "claims": {
    "sub": "user123",
    "exp": 1234567890,
    "iat": 1234567890,
    "jti": "550e8400-e29b-41d4-a716-446655440000"
  },
  "revoked": false,
  "message": "Token is valid and not revoked"
}
```

**Response (Revoked Token):**
```json
{
  "valid": false,
  "claims": {...},
  "revoked": true,
  "message": "Token has been revoked"
}
```

**Example:**
```bash
curl -X POST http://localhost:8000/token/validate \
  -H "Content-Type: application/json" \
  -d '{"token": "YOUR_TOKEN_HERE", "check_revocation": true}'
```

---

### 4. Inspect Token

**GET** `/token/inspect?token=YOUR_TOKEN`

Inspect token claims without full validation (debugging only).

**Response:**
```json
{
  "claims": {
    "sub": "user123",
    "exp": 1234567890,
    "jti": "550e8400-e29b-41d4-a716-446655440000"
  },
  "revoked": false,
  "revocation_reason": null,
  "note": "This is an unverified inspection. Use /token/validate for full validation."
}
```

---

### 5. Revoke Token

**POST** `/revoke`

Revoke tokens by JTI, subject, or key ID.

**Request Body:**
```json
{
  "type": "revoke_jti",
  "value": "550e8400-e29b-41d4-a716-446655440000",
  "ttl_seconds": 3600
}
```

**Revocation Types:**
- `revoke_jti` - Revoke specific token by JWT ID
- `revoke_sub` - Revoke all tokens for a subject (user)
- `revoke_kid` - Revoke all tokens signed with a key

**Response:**
```json
{
  "event_id": "660e8400-e29b-41d4-a716-446655440001",
  "published": true
}
```

**Examples:**

Revoke specific token:
```bash
curl -X POST http://localhost:8000/revoke \
  -H "Content-Type: application/json" \
  -d '{"type": "revoke_jti", "value": "TOKEN_JTI"}'
```

Revoke all tokens for a user:
```bash
curl -X POST http://localhost:8000/revoke \
  -H "Content-Type: application/json" \
  -d '{"type": "revoke_sub", "value": "user123"}'
```

Temporary revocation (auto-expires after 1 hour):
```bash
curl -X POST http://localhost:8000/revoke \
  -H "Content-Type: application/json" \
  -d '{"type": "revoke_jti", "value": "TOKEN_JTI", "ttl_seconds": 3600}'
```

---

### 6. Create Refresh Token

**POST** `/token/refresh/create`

Create a refresh token with client binding and Kyber forward secrecy.

**Request Body:**
```json
{
  "subject": "user123",
  "client_binding": "device-fingerprint-abc123",
  "additional_claims": {
    "role": "user"
  }
}
```

**Response:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800,
  "refresh_expires_in": 7776000,
  "refresh_jti": "770e8400-e29b-41d4-a716-446655440002",
  "access_jti": "880e8400-e29b-41d4-a716-446655440003",
  "subject": "user123",
  "kyber_public_key": "dGVzdC1wdWJsaWMta2V5LWJhc2U2NA=="
}
```

**Example:**
```bash
curl -X POST http://localhost:8000/token/refresh/create \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "user123",
    "client_binding": "device-fingerprint-abc123"
  }'
```

---

### 7. Refresh Access Token

**POST** `/token/refresh`

Refresh access token using refresh token with Kyber forward secrecy.

**Request Body:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "client_binding": "device-fingerprint-abc123",
  "client_public_key": "dGVzdC1wdWJsaWMta2V5LWJhc2U2NA=="
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": null,
  "token_type": "bearer",
  "expires_in": 1800,
  "server_public_key": "c2VydmVyLXB1YmxpYy1rZXktYmFzZTY0",
  "encrypted_session_key": "encrypted-session-key-here",
  "access_jti": "990e8400-e29b-41d4-a716-446655440004"
}
```

---

### 8. Revoke Refresh Token

**POST** `/token/refresh/revoke`

Revoke a refresh token (logout).

**Request Body:**
```
"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Response:**
```json
{
  "event_id": "aa0e8400-e29b-41d4-a716-446655440005",
  "published": true
}
```

**Example:**
```bash
curl -X POST http://localhost:8000/token/refresh/revoke \
  -H "Content-Type: application/json" \
  -d '"YOUR_REFRESH_TOKEN"'
```

---

## Client Integration

### Python Client Example

```python
import requests

BASE_URL = "http://localhost:8000"

# 1. Create access token
response = requests.post(
    f"{BASE_URL}/token",
    json={"subject": "user123"}
)
token_data = response.json()
access_token = token_data["access_token"]
jti = token_data["jti"]

# 2. Validate token
validation = requests.post(
    f"{BASE_URL}/token/validate",
    json={
        "token": access_token,
        "check_revocation": True
    }
).json()

if validation["valid"]:
    print("Token is valid!")

# 3. Use token for API calls
headers = {"Authorization": f"Bearer {access_token}"}
api_response = requests.get(
    "https://api.example.com/data",
    headers=headers
)

# 4. Revoke token (logout)
requests.post(
    f"{BASE_URL}/revoke",
    json={
        "type": "revoke_jti",
        "value": jti
    }
)
```

### JavaScript/TypeScript Client Example

```typescript
const BASE_URL = "http://localhost:8000";

// 1. Create access token
const tokenResponse = await fetch(`${BASE_URL}/token`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ subject: "user123" })
});
const tokenData = await tokenResponse.json();
const accessToken = tokenData.access_token;

// 2. Validate token
const validationResponse = await fetch(`${BASE_URL}/token/validate`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    token: accessToken,
    check_revocation: true
  })
});
const validation = await validationResponse.json();

// 3. Use token
const apiResponse = await fetch("https://api.example.com/data", {
  headers: { "Authorization": `Bearer ${accessToken}` }
});

// 4. Revoke token
await fetch(`${BASE_URL}/revoke`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    type: "revoke_jti",
    value: tokenData.jti
  })
});
```

### Refresh Token Flow Example

```python
import requests
from app.pqc_crypto import KyberKeyExchange

BASE_URL = "http://localhost:8000"

# 1. Login and get refresh token
device_id = "device-fingerprint-abc123"
response = requests.post(
    f"{BASE_URL}/token/refresh/create",
    json={
        "subject": "user123",
        "client_binding": device_id
    }
)
tokens = response.json()

refresh_token = tokens["refresh_token"]
server_kyber_key = tokens["kyber_public_key"]

# Store securely (encrypted)
save_refresh_token(refresh_token)

# 2. When access token expires, refresh it
def refresh_access_token():
    # Generate client key pair
    client_private_key, client_public_key = KyberKeyExchange.generate_keypair()
    client_pub_encoded = KyberKeyExchange.encode_public_key(client_public_key)
    
    response = requests.post(
        f"{BASE_URL}/token/refresh",
        json={
            "refresh_token": refresh_token,
            "client_binding": device_id,
            "client_public_key": client_pub_encoded
        }
    )
    
    if response.status_code == 200:
        data = response.json()
        
        # Derive shared secret
        server_pub = KyberKeyExchange.decode_public_key(data["server_public_key"])
        shared_secret = KyberKeyExchange.derive_shared_secret(
            client_private_key,
            server_pub
        )
        
        return data["access_token"], shared_secret
    else:
        # Refresh token expired or revoked - need to re-login
        return None, None
```

---

## Deployment

### Development

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Production with Gunicorn

```bash
pip install gunicorn

gunicorn app.main:app \
  -w 4 \
  -k uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --timeout 120 \
  --access-logfile - \
  --error-logfile -
```

### Docker Deployment

**Dockerfile:**
```dockerfile
FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["gunicorn", "app.main:app", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000"]
```

**Build and run:**
```bash
docker build -t revocation-service .
docker run -p 8000:8000 \
  -e JWT_SECRET_KEY="your-secret-key" \
  -e REDIS_URL="redis://redis-host:6379/0" \
  -e KAFKA_BOOTSTRAP="kafka-host:29092" \
  revocation-service
```

### Docker Compose (Full Stack)

```yaml
version: '3.8'

services:
  redis:
    image: redis:7
    ports:
      - "6379:6379"

  zookeeper:
    image: confluentinc/cp-zookeeper:7.6.1
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181

  kafka:
    image: confluentinc/cp-kafka:7.6.1
    depends_on:
      - zookeeper
    ports:
      - "29092:29092"
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: "zookeeper:2181"
      KAFKA_LISTENERS: "PLAINTEXT://0.0.0.0:9092,PLAINTEXT_HOST://0.0.0.0:29092"
      KAFKA_ADVERTISED_LISTENERS: "PLAINTEXT://kafka:9092,PLAINTEXT_HOST://localhost:29092"
      KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: "PLAINTEXT:PLAINTEXT,PLAINTEXT_HOST:PLAINTEXT"
      KAFKA_INTER_BROKER_LISTENER_NAME: "PLAINTEXT"
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
      KAFKA_AUTO_CREATE_TOPICS_ENABLE: "true"

  api:
    build: .
    ports:
      - "8000:8000"
    depends_on:
      - redis
      - kafka
    environment:
      - REDIS_URL=redis://redis:6379/0
      - KAFKA_BOOTSTRAP=kafka:9092
      - JWT_SECRET_KEY=${JWT_SECRET_KEY}

  consumer:
    build: .
    command: python -m consumer.consumer
    depends_on:
      - redis
      - kafka
    environment:
      - REDIS_URL=redis://redis:6379/0
      - KAFKA_BOOTSTRAP=kafka:9092
```

### Environment-Specific Configuration

**Development:**
- Single worker
- Reload on code changes
- Debug logging
- Local Redis/Kafka

**Production:**
- Multiple workers (4-8)
- No reload
- Structured logging
- External Redis/Kafka cluster
- HTTPS/SSL
- Rate limiting
- Monitoring & alerting

---

## Troubleshooting

### Common Issues

#### 1. "Service not ready" (503 Error)

**Problem:** Redis or Kafka not connected.

**Solution:**
```bash
# Check Redis
redis-cli ping
# Should return: PONG

# Check Kafka
docker ps | grep kafka

# Verify connection in code
# Check app/main.py startup logs
```

#### 2. Token Always Shows as Expired

**Problem:** Clock skew or token creation issue.

**Solution:**
```bash
# Check server time
date

# Verify token expiration in /token/inspect
curl "http://localhost:8000/token/inspect?token=YOUR_TOKEN"
```

#### 3. Revocation Not Working

**Problem:** Redis keys not being set or checked correctly.

**Solution:**
```bash
# Check Redis keys
redis-cli
> KEYS revoked:*
> GET revoked:jti:YOUR_JTI

# Verify revocation was created
# Check SQLite database
sqlite3 revocation.db "SELECT * FROM revocation_events ORDER BY ts DESC LIMIT 5;"
```

#### 4. Kafka Consumer Not Processing Events

**Problem:** Consumer not running or Kafka connection issue.

**Solution:**
```bash
# Check consumer is running
ps aux | grep consumer

# Check Kafka topics
docker exec -it p4-kafka kafka-topics --list --bootstrap-server localhost:29092

# Restart consumer
python -m consumer.consumer
```

#### 5. Import Errors

**Problem:** Missing dependencies or wrong Python version.

**Solution:**
```bash
# Verify Python version
python --version  # Should be 3.8+

# Reinstall dependencies
pip install --upgrade -r requirements.txt

# Check virtual environment
which python  # Should point to .venv
```

### Debugging Tools

#### Check Redis State
```bash
redis-cli
> KEYS *
> GET revoked:jti:YOUR_JTI
> TTL revoked:jti:YOUR_JTI
```

#### Check SQLite Database
```bash
sqlite3 revocation.db

# View recent revocation events
SELECT * FROM revocation_events ORDER BY ts DESC LIMIT 10;

# View refresh tokens
SELECT * FROM refresh_tokens WHERE revoked = 0;
```

#### Check Kafka Topics
```bash
docker exec -it p4-kafka kafka-console-consumer \
  --bootstrap-server localhost:29092 \
  --topic revocations \
  --from-beginning
```

#### Inspect Token
```bash
curl "http://localhost:8000/token/inspect?token=YOUR_TOKEN"
```

---

## Security Best Practices

### 1. Secret Key Management

⚠️ **NEVER commit secret keys to version control!**

```bash
# Use environment variables
export JWT_SECRET_KEY="$(openssl rand -hex 32)"

# Or use secrets management (AWS Secrets Manager, HashiCorp Vault, etc.)
```

### 2. HTTPS in Production

Always use HTTPS in production:

```python
# Use reverse proxy (nginx, traefik)
# Or configure uvicorn with SSL
uvicorn app.main:app \
  --ssl-keyfile /path/to/key.pem \
  --ssl-certfile /path/to/cert.pem
```

### 3. Rate Limiting

Implement rate limiting to prevent abuse:

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/token")
@limiter.limit("10/minute")
async def create_token(...):
    ...
```

### 4. Token Storage

**Client-side:**
- ✅ Use httpOnly cookies (recommended)
- ✅ Use secure storage (Keychain on iOS, Keystore on Android)
- ❌ Never store in localStorage (XSS vulnerable)

**Server-side:**
- Encrypt refresh tokens at rest
- Use secure database connections
- Regular security audits

### 5. Monitoring & Logging

```python
# Log all revocation events
# Monitor failed validation attempts
# Alert on suspicious patterns
```

### 6. Regular Key Rotation

Rotate `JWT_SECRET_KEY` periodically:

1. Generate new key
2. Update environment variable
3. New tokens use new key
4. Old tokens continue to work (or revoke them)

### 7. Database Backups

```bash
# Backup SQLite database regularly
cp revocation.db revocation.db.backup.$(date +%Y%m%d)
```

---

## API Testing

### Using cURL

```bash
# Create token
TOKEN=$(curl -s -X POST http://localhost:8000/token \
  -H "Content-Type: application/json" \
  -d '{"subject": "test"}' | jq -r '.access_token')

# Validate token
curl -X POST http://localhost:8000/token/validate \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"$TOKEN\", \"check_revocation\": true}"

# Revoke token
JTI=$(curl -s -X POST http://localhost:8000/token \
  -H "Content-Type: application/json" \
  -d '{"subject": "test"}' | jq -r '.jti')

curl -X POST http://localhost:8000/revoke \
  -H "Content-Type: application/json" \
  -d "{\"type\": \"revoke_jti\", \"value\": \"$JTI\"}"
```

### Using Swagger UI

Visit `http://localhost:8000/docs` for interactive API documentation.

### Using Postman

Import the API schema from `http://localhost:8000/openapi.json`

---

## Project Structure

```
revocation/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration
│   ├── models.py            # Pydantic models
│   ├── jwt_utils.py         # JWT operations
│   ├── refresh_token_utils.py  # Refresh token logic
│   ├── pqc_crypto.py        # Post-quantum crypto
│   ├── kafka_pub.py         # Kafka publisher
│   └── store_sqlite.py      # SQLite operations
├── consumer/
│   ├── __init__.py
│   └── consumer.py          # Kafka consumer
├── scripts/
│   └── schema.sql           # Database schema
├── docker-compose.yml       # Infrastructure setup
├── requirements.txt         # Python dependencies
├── start.sh                 # Linux/Mac startup
├── start.bat                # Windows startup
├── .gitignore
├── README.md
├── API_ENDPOINTS_GUIDE.md
├── IMPLEMENTATION_GUIDE.md
├── REVOKE_ENDPOINT_EXPLAINED.md
└── COMPLETE_IMPLEMENTATION_GUIDE.md (this file)
```

---

## Next Steps

1. ✅ **Set up the service** using this guide
2. ✅ **Test the API** using Swagger UI or cURL
3. ✅ **Integrate with your application** using client examples
4. ✅ **Configure production settings** (secret keys, HTTPS, etc.)
5. ✅ **Set up monitoring** and logging
6. ✅ **Plan for scaling** (Redis cluster, Kafka cluster, load balancing)

---

## Support & Resources

- **API Documentation**: `http://localhost:8000/docs`
- **OpenAPI Schema**: `http://localhost:8000/openapi.json`
- **Project README**: `README.md`
- **Endpoint Details**: `API_ENDPOINTS_GUIDE.md`
- **Revocation Details**: `REVOKE_ENDPOINT_EXPLAINED.md`

---

## License

[Your License Here]

---

**Last Updated**: 2024
**Version**: 1.0

