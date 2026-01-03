# Quick Start Guide - E-JWKS Merkle Tree System

python3 -m venv .venv

source .venv/bin/activate



## 🚀 Start the System

### Option 1: Docker Compose (Recommended)
```bash
# Create data directory
mkdir -p data

# Start both Redis and API
docker compose up -d

# View logs
docker compose logs -f ejwks-api

# Check health
curl http://localhost:8000/health
```

### Option 2: Local Development
```bash
# Start Redis
docker compose up -d redis

# Install dependencies
pip install -r requirements.txt

# Run the API
uvicorn app.main:app --reload --port 8000
```

---

## 📝 Basic Usage

### 1. Import a Key

curl -X POST http://localhost:8000/internal/keys/import \
  -H "Content-Type: application/json" \
  -d '{
    "kid": "demo-dilithium-1",
    "kty": "OKP",
    "crv": "Dilithium2",
    "alg": "Dilithium2",
    "x": "tqI0-7q9yE_0pQ3uD4s1M6V_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

### 2. Get JWKS Root
```bash
curl http://localhost:8000/jwks/root | jq
```

### 3. Get Key with Proof
```bash
curl http://localhost:8000/jwks/proof/my-key-1 | jq
```

### 4. Verify Key (Client-Side)
```bash
python client_verify.py --kid my-key-1
```

### 5. Check Transparency Log
```bash
# Get latest checkpoint
curl http://localhost:8000/log/latest | jq

# Get specific checkpoint
curl http://localhost:8000/log/checkpoint/1 | jq
```

---

## �� Testing the Fixes

### Test 1: Response Schema (Fixed Issue #1)
```bash
# This should now return "root" instead of "jwks_root"
curl http://localhost:8000/jwks/proof/my-key-1 | jq '.root'
```

### Test 2: Client Verification (Fixed Issue #8)
```bash
# This should auto-load the pinned key from root_signer_key.json
python client_verify.py --kid my-key-1
```

### Test 3: Input Validation (Fixed Issue #4)
```bash
# This should fail with validation error
curl -X POST http://localhost:8000/internal/keys/import \
  -H "Content-Type: application/json" \
  -d '{
    "kid": "invalid!@#$%^&*()",
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "test"
  }'
```

### Test 4: Checkpoint Integrity (Fixed Issue #6)
```bash
# Check logs for checkpoint verification
docker compose logs ejwks-api | grep checkpoint
```

---

## 📊 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/jwks.json` | GET | Legacy JWKS format |
| `/jwks/root` | GET | Signed JWKS root bundle |
| `/jwks/proof/{kid}` | GET | Key + Merkle proof |
| `/internal/keys/import` | POST | Import new key (admin) |
| `/log/root` | GET | Transparency log root |
| `/log/latest` | GET | Latest checkpoint + proof |
| `/log/checkpoint/{idx}` | GET | Specific checkpoint + proof |

---

## 🔍 Monitoring

### View Logs
```bash
# All services
docker compose logs -f

# Just API
docker compose logs -f ejwks-api

# Filter by level
docker compose logs ejwks-api | grep ERROR
```

### Check Database
```bash
# Keys count
sqlite3 data/keys.db "SELECT COUNT(*) FROM keys;"

# Checkpoints count
sqlite3 data/keys.db "SELECT COUNT(*) FROM checkpoints;"

# View all keys
sqlite3 data/keys.db "SELECT kid, kty FROM keys;"
```

### Check Redis Cache
```bash
docker compose exec redis redis-cli

# In redis-cli:
KEYS *
GET root:jwks_bundle
```

---

## 🛠️ Troubleshooting

### Problem: Client verification fails
**Solution:** Ensure root_signer_key.json exists in current directory
```bash
ls -la root_signer_key.json
```

### Problem: Redis connection error
**Solution:** Check Redis is running
```bash
docker compose ps redis
docker compose logs redis
```

### Problem: Database locked
**Solution:** Only one process can write at a time
```bash
# Stop all processes
docker compose down
# Restart
docker compose up -d
```

### Problem: Import fails with validation error
**Solution:** Check kid format (alphanumeric, dash, underscore, dot only)
```bash
# Valid:   "my-key-1", "key_123", "key.prod"
# Invalid: "key@prod", "key#1", "key with spaces"
```

---

## 📚 Architecture Files

- `app/main.py` - FastAPI routes and startup
- `app/service.py` - Business logic layer
- `app/merkle.py` - Merkle tree implementation
- `app/log_merkle.py` - Transparency log tree
- `app/storage.py` - SQLite database layer
- `app/signer.py` - Cryptographic signing
- `app/bloom.py` - Bloom filter for DoS protection
- `client_verify.py` - Client-side verification script

---

## 🎓 Research Notes

This implementation is suitable for academic research because:

1. **Cryptographic Security**: Domain separation prevents attacks
2. **Transparency**: All changes are logged and verifiable
3. **Verifiability**: Clients can independently verify keys
4. **Tamper Detection**: Checkpoint chain detects database modifications
5. **DoS Protection**: Bloom filters prevent resource exhaustion

### Citation Suggestion
```
@software{ejwks_merkle_2025,
  title={Enhanced JWKS with Merkle Proofs and Transparency Log},
  author={Your Name},
  year={2025},
  note={Research implementation for secure key distribution}
}
```

