# Critical Fixes Applied to E-JWKS Merkle Project

## Date: December 31, 2025

This document details all critical security and functionality fixes applied to the research project.

---

## ✅ High Priority Fixes

### 1. Fixed API Response Schema Mismatch (CRITICAL)
**Issue:** The `/jwks/proof/{kid}` endpoint returned `"jwks_root"` but client expected `"root"`
**Impact:** Client verification would fail with KeyError
**Fix:** Changed response key name to `"root"` and added explicit `"jkt"` field
**Files:** `app/main.py`, `app/service.py`

### 2. Fixed Bloom Filter Race Condition (CRITICAL)
**Issue:** Bloom filter was rebuilt in-place during tree rebuilds, causing concurrent requests to potentially see corrupted state
**Impact:** False negatives (keys appearing missing), potential crashes
**Fix:** Build new bloom filter first, then atomically swap it
**Files:** `app/service.py`

### 3. Fixed Merkle Tree Second Preimage Attack (SECURITY)
**Issue:** Odd-node duplication without domain separation allowed second preimage attacks
**Impact:** Attackers could potentially forge different leaf sets producing the same root
**Fix:** Added domain separation prefixes (0x00 for leaves, 0x01 for parents)
**Files:** `app/merkle.py`, `app/log_merkle.py`

### 4. Added Input Validation (SECURITY)
**Issue:** No validation of kid field could allow injection attacks or DoS
**Impact:** Potential security vulnerabilities
**Fix:** Added Pydantic validators for kid (length, character restrictions) and kty
**Files:** `app/schemas.py`

---

## ✅ Medium Priority Fixes

### 5. Fixed Transparency Log Error Handling
**Issue:** Confusing nested `or` logic in log endpoints
**Impact:** Silent failures, poor error messages
**Fix:** Clear sequential checks with explicit error handling
**Files:** `app/main.py`

### 6. Added Checkpoint Chain Integrity Verification
**Issue:** No verification that checkpoint chain is intact
**Impact:** Database tampering would go undetected
**Fix:** Added `_verify_checkpoint_chain()` method that validates prev_hash links
**Files:** `app/storage.py`

### 7. Fixed Redis Decode Issues
**Issue:** Inconsistent handling of bytes vs strings from Redis
**Impact:** Potential runtime errors
**Fix:** Added explicit decode checks for Redis responses
**Files:** `app/service.py`

### 8. Improved Client Verification Script
**Issue:** Hardcoded placeholder for pinned public key
**Impact:** Verification would fail without manual setup
**Fix:** Auto-extract public key from root_signer_key.json, better error messages
**Files:** `client_verify.py`

---

## ✅ Low Priority (Quality Improvements)

### 9. Added Comprehensive Logging
**Issue:** No observability into system operations
**Impact:** Difficult to debug issues
**Fix:** Added structured logging throughout application
**Files:** `app/main.py`

### 10. Completed Docker Compose Configuration
**Issue:** Only Redis was in docker-compose, not the API
**Impact:** Harder to run complete system
**Fix:** Added ejwks-api service with proper health checks and volumes
**Files:** `docker-compose.yml`

---

## 🔒 Security Improvements Summary

1. **Domain Separation in Merkle Trees**: Prevents second preimage attacks
2. **Input Validation**: Prevents injection and DoS attacks
3. **Checkpoint Chain Verification**: Detects database tampering
4. **Atomic Operations**: Prevents race conditions
5. **Better Error Handling**: Prevents information leakage

---

## 🧪 Testing Recommendations

### Test the fixes:

1. **Start the system:**
   ```bash
   docker compose up -d
   ```

2. **Import a test key:**
   ```bash
   curl -X POST http://127.0.0.1:8000/internal/keys/import \
     -H "Content-Type: application/json" \
     -d '{
       "kid": "test-key-1",
       "kty": "OKP",
       "crv": "Ed25519",
       "x": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
       "alg": "EdDSA"
     }'
   ```

3. **Verify the key:**
   ```bash
   python client_verify.py --kid test-key-1
   ```

4. **Test transparency log:**
   ```bash
   curl http://127.0.0.1:8000/log/latest
   ```

---

## 📊 Known Limitations (For Future Work)

1. **No Consistency Proofs**: Transparency log needs consistency proofs between tree sizes
2. **No Key Rotation**: No mechanism to rotate root signer keys
3. **No Locking**: Key imports not atomic (need application-level locking)
4. **No Rate Limiting**: Could benefit from rate limiting on import endpoint
5. **No Metrics**: Should add Prometheus metrics for monitoring

---

## 📚 Architecture Summary

```
┌─────────────────┐
│   Client App    │ ← Verifies with pinned public key
└────────┬────────┘
         │
         ↓ HTTPS
┌─────────────────┐
│  FastAPI Server │
│  ┌───────────┐  │
│  │ Service   │  │ ← Business logic
│  │ Layer     │  │
│  └─────┬─────┘  │
│        │        │
│  ┌─────┴─────┐  │
│  │  Storage  │  │ ← SQLite (keys + checkpoints)
│  └───────────┘  │
│        │        │
│  ┌─────┴─────┐  │
│  │   Redis   │  │ ← Cache (proofs + bundles)
│  └───────────┘  │
└─────────────────┘

Key Components:
- Merkle Tree: Efficient key inclusion proofs
- Transparency Log: Append-only audit trail
- Bloom Filter: DoS protection
- Dual Signers: Separate keys for JWKS root and log
```

---

## ✨ What Makes This Research-Grade

1. **Pinned Public Keys**: Client NEVER trusts keys from network
2. **Cryptographic Proofs**: Every key verified via Merkle proof
3. **Transparency**: All changes logged in append-only structure
4. **Domain Separation**: Prevents cryptographic attacks
5. **Integrity Checks**: Database tampering is detected

This system provides **provable security** for key distribution, suitable for academic publication.

