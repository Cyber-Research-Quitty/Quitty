# Revoke Endpoint - Complete Explanation

This document explains what happens when you call the `/revoke` endpoint and what the "Reset" button does in Swagger UI.

---

## POST `/revoke` Endpoint - Step by Step

### Request Format

```json
{
  "type": "revoke_jti",        // or "revoke_sub" or "revoke_kid"
  "value": "token-id-here",    // The JTI, subject, or key ID to revoke
  "ttl_seconds": 3600           // Optional: Auto-expire revocation (30 seconds to 30 days)
}
```

### What Happens When You Call `/revoke`

When you send a POST request to `/revoke`, the following happens **in order**:

#### Step 1: Request Validation
```python
# Checks:
- Service is ready (Redis and Kafka connected)
- Request format is valid
- Type is one of: "revoke_jti", "revoke_sub", "revoke_kid"
- Value is provided (1-512 characters)
- ttl_seconds is optional (30 seconds to 30 days if provided)
```

#### Step 2: Generate Revocation Event
```python
event_id = str(uuid.uuid4())           # Unique event ID
nonce = secrets.token_urlsafe(16)      # Replay protection
ts = utc_now_iso()                      # Timestamp

# Create unsigned event
unsigned = {
    "event_id": event_id,
    "type": req.type,                   # e.g., "revoke_jti"
    "value": req.value,                 # e.g., token JTI
    "ts": ts,
    "nonce": nonce,
    "kid": PQC_SIGNING_KEY_ID,          # Key ID for signing
}
```

#### Step 3: Sign the Event
```python
# Sign with Dilithium (PQC signature)
sig = dilithium_sign(canonical_bytes(unsigned))

# Add signature to event
event = dict(unsigned)
event["sig"] = sig
```

#### Step 4: Store in SQLite (Durable Audit Log)
```python
# Permanent record in revocation_events table
insert_event(event)
```

**What's stored:**
- `event_id` - Unique identifier
- `type` - Revocation type (revoke_jti/sub/kid)
- `value` - What was revoked
- `ts` - Timestamp
- `nonce` - Replay protection
- `kid` - Signing key ID
- `sig` - Cryptographic signature

**Why SQLite?**
- **Permanent audit trail** - Cannot be deleted
- **Compliance** - Legal/regulatory requirements
- **Forensics** - Security incident investigation
- **Analytics** - Historical revocation data

#### Step 5: Update Redis Cache (Fast Enforcement)
```python
# Extract keyspace from type
keyspace = req.type.split("_")[1]  # "revoke_jti" -> "jti"

# Create Redis key
redis_key = f"revoked:{keyspace}:{req.value}"

# Store in Redis
if req.ttl_seconds:
    # Temporary revocation (auto-expires)
    await rds.setex(redis_key, req.ttl_seconds, "1")
else:
    # Permanent revocation
    await rds.set(redis_key, "1")
```

**Redis Keys Created:**
- `revoked:jti:{jti}` - Revoke specific token
- `revoked:sub:{subject}` - Revoke all tokens for user
- `revoked:kid:{key_id}` - Revoke all tokens for key

**Why Redis?**
- **Fast lookups** - O(1) time complexity
- **Real-time enforcement** - Immediate effect
- **Scalable** - Handles millions of revocations
- **TTL support** - Auto-expire temporary revocations

#### Step 6: Publish to Kafka (Event Streaming)
```python
# Broadcast to all services
await publish_event(producer, canonical_bytes(event))
```

**What happens:**
- Event is published to `revocations` topic
- All Kafka consumers receive the event
- Other services update their Redis caches
- Fast propagation across microservices

**Why Kafka?**
- **Event-driven architecture** - Decoupled services
- **Fast propagation** - Real-time updates
- **Scalability** - Multiple consumers
- **Reliability** - Message persistence

#### Step 7: Return Response
```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "published": true
}
```

---

## Revocation Types Explained

### 1. `revoke_jti` - Revoke Specific Token

**Request:**
```json
{
  "type": "revoke_jti",
  "value": "7de1b319-5a54-4b80-8eeb-34b46852ad15"
}
```

**What happens:**
- Only this specific token is revoked
- Other tokens for the same user remain valid
- Redis key: `revoked:jti:7de1b319-5a54-4b80-8eeb-34b46852ad15`

**Use cases:**
- Single compromised token
- Logout from one device
- Token theft incident

**Example:**
```python
# User reports token stolen
token_jti = "7de1b319-5a54-4b80-8eeb-34b46852ad15"
requests.post("/revoke", json={
    "type": "revoke_jti",
    "value": token_jti
})
# Only this token is invalidated
```

---

### 2. `revoke_sub` - Revoke All Tokens for User

**Request:**
```json
{
  "type": "revoke_sub",
  "value": "user123"
}
```

**What happens:**
- **ALL tokens** for this user are revoked
- Future tokens for this user are also revoked (until cleared)
- Redis key: `revoked:sub:user123`

**Use cases:**
- User logout from all devices
- Password change
- Account suspension
- Security breach

**Example:**
```python
# User changes password - logout everywhere
user_id = "user123"
requests.post("/revoke", json={
    "type": "revoke_sub",
    "value": user_id
})
# ALL tokens for user123 are now invalid
```

**⚠️ Important:** This affects ALL tokens (past, present, and future) for this subject until the revocation is cleared.

---

### 3. `revoke_kid` - Revoke All Tokens for Key

**Request:**
```json
{
  "type": "revoke_kid",
  "value": "p4-dilithium-key-1"
}
```

**What happens:**
- **ALL tokens** signed with this key are revoked
- Used for key rotation or key compromise
- Redis key: `revoked:kid:p4-dilithium-key-1`

**Use cases:**
- Key compromise
- Key rotation
- Security incident
- Certificate expiration

**Example:**
```python
# Key compromised - revoke all tokens
key_id = "p4-dilithium-key-1"
requests.post("/revoke", json={
    "type": "revoke_kid",
    "value": key_id
})
# ALL tokens signed with this key are invalid
```

---

## TTL (Time To Live) - Temporary Revocations

### Permanent Revocation (Default)
```json
{
  "type": "revoke_jti",
  "value": "token-id"
  // No ttl_seconds = permanent
}
```
- Revocation never expires
- Must be manually cleared
- Redis key: `revoked:jti:{jti}` (no expiration)

### Temporary Revocation
```json
{
  "type": "revoke_jti",
  "value": "token-id",
  "ttl_seconds": 3600  // Auto-expire after 1 hour
}
```
- Revocation expires automatically
- Redis key: `revoked:jti:{jti}` (expires in 3600 seconds)
- After expiration, token becomes valid again (if not expired)

**Use cases:**
- Temporary account suspension
- Rate limiting
- Security cooldown period

---

## What Happens After Revocation

### Immediate Effects (Within milliseconds)

1. **Redis Updated** - Token marked as revoked
2. **SQLite Logged** - Permanent audit record
3. **Kafka Published** - Event broadcast

### Validation Checks

When a token is validated (`/token/validate`), the system checks:

```python
# 1. Check if specific token is revoked
if redis.get(f"revoked:jti:{jti}"):
    return "Token has been revoked"

# 2. Check if user is revoked
if redis.get(f"revoked:sub:{sub}"):
    return "Token has been revoked (all tokens for this subject are revoked)"

# 3. Check if key is revoked
if redis.get(f"revoked:kid:{kid}"):
    return "Token has been revoked (all tokens for this key are revoked)"
```

### Propagation

1. **Kafka Consumer** receives event
2. **Updates Redis** in all services
3. **All services** now reject the token
4. **Consistent state** across microservices

---

## The "Reset" Button in Swagger UI

### What is the Reset Button?

The **"Reset"** button in Swagger UI (at `/docs`) is a **UI feature**, not an API endpoint. It's part of the Swagger interface.

### What Does It Do?

The Reset button **clears the form fields** in the Swagger UI interface. It does **NOT**:
- ❌ Revoke any tokens
- ❌ Clear Redis
- ❌ Delete SQLite records
- ❌ Call any API endpoint
- ❌ Affect your server

### What It Actually Does:

1. **Clears input fields** - Removes text from request body
2. **Resets form state** - Returns to default values
3. **UI only** - Only affects the browser interface

### Visual Example:

**Before Reset:**
```
Request body:
{
  "type": "revoke_jti",
  "value": "7de1b319-5a54-4b80-8eeb-34b46852ad15",
  "ttl_seconds": 3600
}
```

**After Reset:**
```
Request body:
{
  "type": "revoke_jti",
  "value": "",              // Cleared
  "ttl_seconds": null       // Cleared
}
```

### When to Use Reset Button:

- ✅ You want to clear the form and start over
- ✅ You made a mistake typing
- ✅ You want to test with different values
- ✅ You want to see the default request format

### What Reset Button Does NOT Do:

- ❌ It does NOT undo a revocation
- ❌ It does NOT clear Redis
- ❌ It does NOT delete audit logs
- ❌ It does NOT affect already-revoked tokens

---

## How to Actually Clear/Undo a Revocation

If you want to **undo a revocation** (make tokens valid again), you need to:

### Option 1: Delete from Redis (Temporary)
```python
import redis.asyncio as redis

async def clear_revocation():
    rds = redis.from_url("redis://localhost:6379/0")
    
    # Clear specific revocation
    await rds.delete("revoked:jti:token-id")
    # or
    await rds.delete("revoked:sub:user123")
```

### Option 2: Use the Clear Script
```bash
python clear_revocation.py --subject user123
python clear_revocation.py --jti token-id
```

### Option 3: Wait for TTL (if temporary revocation)
If you used `ttl_seconds`, the revocation will auto-expire.

**Note:** SQLite audit log entries are **permanent** and cannot be deleted (by design for audit compliance).

---

## Complete Flow Diagram

```
User calls /revoke
    │
    ├─► Validate request
    │
    ├─► Generate event (event_id, nonce, timestamp)
    │
    ├─► Sign event (Dilithium signature)
    │
    ├─► Store in SQLite (permanent audit log)
    │   └─► revocation_events table
    │
    ├─► Update Redis (fast cache)
    │   └─► revoked:{type}:{value} = "1"
    │
    ├─► Publish to Kafka (event streaming)
    │   └─► revocations topic
    │
    └─► Return response
        └─► {event_id, published: true}

Kafka Consumer (separate process)
    │
    ├─► Receives event
    │
    ├─► Verifies signature
    │
    └─► Updates Redis in all services
        └─► revoked:{type}:{value} = "1"
```

---

## Example: Complete Revocation Flow

### Step 1: Create a Token
```bash
POST /token
{
  "subject": "user123"
}

Response:
{
  "access_token": "eyJ...",
  "jti": "abc-123-def"
}
```

### Step 2: Validate Token (Should be valid)
```bash
POST /token/validate
{
  "token": "eyJ...",
  "check_revocation": true
}

Response:
{
  "valid": true,
  "revoked": false,
  "message": "Token is valid and not revoked"
}
```

### Step 3: Revoke the Token
```bash
POST /revoke
{
  "type": "revoke_jti",
  "value": "abc-123-def"
}

Response:
{
  "event_id": "event-456",
  "published": true
}
```

**What happened:**
1. ✅ Event stored in SQLite
2. ✅ Redis key created: `revoked:jti:abc-123-def = "1"`
3. ✅ Event published to Kafka
4. ✅ All services notified

### Step 4: Validate Token Again (Should be revoked)
```bash
POST /token/validate
{
  "token": "eyJ...",
  "check_revocation": true
}

Response:
{
  "valid": false,
  "revoked": true,
  "message": "Token has been revoked"
}
```

### Step 5: Clear Revocation (if needed)
```bash
python clear_revocation.py --jti abc-123-def
```

### Step 6: Validate Token Again (Should be valid now)
```bash
POST /token/validate
{
  "token": "eyJ...",
  "check_revocation": true
}

Response:
{
  "valid": true,  // If token hasn't expired
  "revoked": false,
  "message": "Token is valid and not revoked"
}
```

---

## Summary

### `/revoke` Endpoint:
- ✅ Creates a signed revocation event
- ✅ Stores in SQLite (permanent audit)
- ✅ Updates Redis (fast enforcement)
- ✅ Publishes to Kafka (propagates to all services)
- ✅ Returns event ID and published status

### Reset Button:
- ✅ Clears form fields in Swagger UI
- ✅ UI-only feature (doesn't affect server)
- ❌ Does NOT revoke tokens
- ❌ Does NOT clear Redis
- ❌ Does NOT undo revocations

### To Undo a Revocation:
- Use `clear_revocation.py` script
- Delete Redis key manually
- Wait for TTL expiration (if temporary)

---

For more information, see:
- `API_ENDPOINTS_GUIDE.md` - Complete API documentation
- `IMPLEMENTATION_GUIDE.md` - Setup and usage guide
- `clear_revocation.py` - Script to clear revocations

