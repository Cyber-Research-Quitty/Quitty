# API Endpoints Guide - Client Documentation

This guide explains each API endpoint in a logical order for client integration.

## Endpoint Overview

The API provides 9 endpoints organized into these categories:
1. **Health & Status** (2 endpoints)
2. **Token Management** (3 endpoints)
3. **Refresh Token Flow** (3 endpoints)
4. **Revocation** (1 endpoint)

---

## Recommended Explanation Order

### Phase 1: Getting Started (Health & Basic Info)

#### 1. GET `/` - Root Endpoint
**Purpose**: Welcome endpoint that provides service information

**When to use**: 
- Initial connection test
- Service discovery
- Health monitoring

**Response Example**:
```json
{
  "service": "p4-revocation",
  "status": "running",
  "docs": "/docs"
}
```

**Client Use Case**: 
```python
# Check if service is available
response = requests.get("http://localhost:8000/")
if response.status_code == 200:
    print("Service is running")
```

---

#### 2. GET `/health` - Health Check
**Purpose**: Simple health check endpoint for monitoring and load balancers

**When to use**:
- Health monitoring systems
- Load balancer health checks
- Automated monitoring scripts

**Response Example**:
```json
{
  "ok": true
}
```

**Client Use Case**:
```python
# Health check for monitoring
response = requests.get("http://localhost:8000/health")
is_healthy = response.json().get("ok", False)
```

---

### Phase 2: Basic Token Operations

#### 3. POST `/token` - Create Access Token
**Purpose**: Generate a new JWT access token for a user

**When to use**:
- User login
- Initial authentication
- Getting a short-lived access token

**Request Body**:
```json
{
  "subject": "user123",                    // Required: User ID
  "expires_minutes": 60,                   // Optional: Custom expiration (default: 30)
  "additional_claims": {                   // Optional: Custom data
    "role": "admin",
    "department": "IT"
  }
}
```

**Response**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600,                      // Seconds until expiration
  "jti": "550e8400-e29b-41d4-a716-446655440000",  // Token ID for revocation
  "subject": "user123"
}
```

**Client Use Case**:
```python
# User login flow
def login(username, password):
    # Verify credentials...
    if credentials_valid:
        token_response = requests.post(
            "http://localhost:8000/token",
            json={"subject": username}
        )
        return token_response.json()["access_token"]
```

**Important Notes**:
- Access tokens are short-lived (default 30 minutes)
- Save the `jti` (JWT ID) if you need to revoke the token later
- Use refresh tokens for long-term sessions

---

#### 4. POST `/token/validate` - Validate Token
**Purpose**: Verify if an access token is valid, not expired, and not revoked

**When to use**:
- Before accessing protected resources
- Token validation in middleware
- Security checks

**Request Body**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "check_revocation": true                 // Optional: Check if revoked (default: true)
}
```

**Response (Valid Token)**:
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

**Response (Invalid/Revoked Token)**:
```json
{
  "valid": false,
  "claims": {...},
  "revoked": true,
  "message": "Token has been revoked"
}
```

**Client Use Case**:
```python
# Validate token before API call
def validate_and_use_token(token):
    validation = requests.post(
        "http://localhost:8000/token/validate",
        json={"token": token, "check_revocation": True}
    ).json()
    
    if validation["valid"] and not validation["revoked"]:
        return True  # Token is good
    else:
        return False  # Need to refresh or re-authenticate
```

---

#### 5. GET `/token/inspect` - Inspect Token
**Purpose**: Decode and view token claims without full validation (debugging tool)

**When to use**:
- Debugging token issues
- Viewing token contents
- Development/testing only

**Query Parameter**:
- `token`: The JWT token to inspect

**Response**:
```json
{
  "claims": {
    "sub": "user123",
    "exp": 1234567890,
    "iat": 1234567890,
    "jti": "550e8400-e29b-41d4-a716-446655440000",
    "iss": "p4-revocation-service",
    "type": "access"
  },
  "note": "This is an unverified inspection. Use /token/validate for full validation."
}
```

**Client Use Case**:
```python
# Debug: See what's in a token
claims = requests.get(
    "http://localhost:8000/token/inspect",
    params={"token": token}
).json()
print(f"Token subject: {claims['claims']['sub']}")
```

**⚠️ Security Note**: This endpoint does NOT verify signature or expiration. Use only for debugging.

---

### Phase 3: Refresh Token Flow (Long-term Sessions)

#### 6. POST `/token/refresh/create` - Create Refresh Token
**Purpose**: Create a long-lived refresh token with client binding for secure token renewal

**When to use**:
- After successful login
- Setting up long-term sessions
- Mobile app authentication
- Remember me functionality

**Request Body**:
```json
{
  "subject": "user123",                    // Required: User ID
  "client_binding": "device-fingerprint-abc123",  // Required: Device identifier
  "additional_claims": {                   // Optional: Custom data
    "role": "admin"
  }
}
```

**Response**:
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800,                      // Access token expiration (seconds)
  "refresh_expires_in": 7776000,           // Refresh token expiration (90 days)
  "refresh_jti": "550e8400-e29b-41d4-a716-446655440000",
  "access_jti": "660e8400-e29b-41d4-a716-446655440001",
  "subject": "user123",
  "client_public_key": "dGVzdC1wdWJsaWMta2V5LWJhc2U2NA=="
}
```

**Client Use Case**:
```python
# Login and get refresh token
def login_with_refresh(username, device_id):
    response = requests.post(
        "http://localhost:8000/token/refresh/create",
        json={
            "subject": username,
            "client_binding": device_id  # e.g., device fingerprint
        }
    )
    tokens = response.json()
    
    # Store securely
    save_refresh_token(tokens["refresh_token"])
    
    return tokens["access_token"]
```

**Key Features**:
- **Client Binding**: Token is bound to specific device/client
- **Long-lived**: Valid for 90 days (configurable)
- **Security**: Cannot be used on different devices
- **Forward Secrecy**: Kyber KEM used during refresh

**Important**: 
- Store `refresh_token` securely (encrypted storage)
- Use same `client_binding` value when refreshing
- Generate a new Kyber KEM key pair per refresh and keep the private key for decapsulation (recommended)
- The `client_public_key` above is a convenience value for quick testing

---

#### 7. POST `/token/refresh` - Refresh Access Token
**Purpose**: Get a new access token using refresh token with Kyber forward secrecy

**When to use**:
- Access token expired
- Periodic token renewal
- Maintaining active session

**Request Body**:
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "client_binding": "device-fingerprint-abc123",  // Must match original
  "client_public_key": "dGVzdC1wdWJsaWMta2V5LWJhc2U2NA=="  // Client's Kyber KEM public key (base64url)
}
```

**Response**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": null,                   // Token rotation (future feature)
  "token_type": "bearer",
  "expires_in": 1800,
  "kem_ciphertext": "c2VydmVyLWNpcGhlcnRleHQtYmFzZTY0",     // Kyber KEM ciphertext
  "encrypted_session_key": "encrypted-session-key-here",
  "access_jti": "770e8400-e29b-41d4-a716-446655440002"
}
```

**Client Use Case**:
```python
from app.pqc_crypto import KyberKeyExchange

def refresh_access_token(refresh_token, device_id):
    # Generate client key pair for forward secrecy
    private_key, public_key = KyberKeyExchange.generate_keypair()
    public_key_encoded = KyberKeyExchange.encode_public_key(public_key)
    
    response = requests.post(
        "http://localhost:8000/token/refresh",
        json={
            "refresh_token": refresh_token,
            "client_binding": device_id,
            "client_public_key": public_key_encoded
        }
    )
    
    if response.status_code == 200:
        data = response.json()
        
        # Decapsulate ciphertext to derive shared secret
        kem_ciphertext = data["kem_ciphertext"]
        ciphertext = KyberKeyExchange.decode_ciphertext(kem_ciphertext)
        shared_secret = KyberKeyExchange.decapsulate(private_key, ciphertext)
        
        # Use shared_secret for secure communication
        return data["access_token"], shared_secret
    
    return None, None
```

**Security Features**:
- **Client Binding Verification**: Ensures token is used on same device
- **Kyber KEM Forward Secrecy**: Each refresh uses a new KEM exchange
- **Automatic Revocation Check**: Verifies token hasn't been revoked

**Error Cases**:
- `401`: Token expired, invalid, or revoked
- `401`: Client binding mismatch (different device)
- `400`: Invalid KEM encapsulation

---

#### 8. POST `/token/refresh/revoke` - Revoke Refresh Token
**Purpose**: Immediately invalidate a refresh token (logout, security breach, etc.)

**When to use**:
- User logout
- Security incident (stolen device)
- Account suspension
- Password change

**Request Body**:
```json
"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."  // Just the refresh token string
```

**Response**:
```json
{
  "event_id": "880e8400-e29b-41d4-a716-446655440003",
  "published": true
}
```

**Client Use Case**:
```python
# Logout flow
def logout(refresh_token):
    response = requests.post(
        "http://localhost:8000/token/refresh/revoke",
        json=refresh_token
    )
    
    if response.status_code == 200:
        # Clear local storage
        clear_refresh_token()
        return True
    return False
```

**What Happens**:
1. Token is marked as revoked in Redis (immediate)
2. Event is logged in SQLite (audit trail)
3. Event is published to Kafka (propagates to other services)
4. All future refresh attempts will fail

---

### Phase 4: Token Revocation

#### 9. POST `/revoke` - Revoke Token
**Purpose**: Revoke tokens by JTI, subject, or key ID

**When to use**:
- Revoke specific access token
- Revoke all tokens for a user
- Revoke all tokens signed with a key
- Security incident response

**Request Body**:
```json
{
  "type": "revoke_jti",                    // "revoke_jti" | "revoke_sub" | "revoke_kid"
  "value": "550e8400-e29b-41d4-a716-446655440000",  // Token ID, user ID, or key ID
  "ttl_seconds": 3600                       // Optional: Auto-expire revocation (default: permanent)
}
```

**Response**:
```json
{
  "event_id": "990e8400-e29b-41d4-a716-446655440004",
  "published": true
}
```

**Revocation Types**:

1. **`revoke_jti`** - Revoke specific token
   ```json
   {
     "type": "revoke_jti",
     "value": "token-jti-here"
   }
   ```
   Use case: Revoke a single compromised token

2. **`revoke_sub`** - Revoke all tokens for a user
   ```json
   {
     "type": "revoke_sub",
     "value": "user123"
   }
   ```
   Use case: User logout from all devices, password change

3. **`revoke_kid`** - Revoke all tokens signed with a key
   ```json
   {
     "type": "revoke_kid",
     "value": "p4-dilithium-key-1"
   }
   ```
   Use case: Key compromise, key rotation

**Client Use Case**:
```python
# Revoke all user tokens (logout everywhere)
def logout_everywhere(user_id):
    response = requests.post(
        "http://localhost:8000/revoke",
        json={
            "type": "revoke_sub",
            "value": user_id
        }
    )
    return response.json()["published"]

# Revoke specific token
def revoke_token(token_jti):
    response = requests.post(
        "http://localhost:8000/revoke",
        json={
            "type": "revoke_jti",
            "value": token_jti,
            "ttl_seconds": 3600  # Auto-expire after 1 hour
        }
    )
    return response.json()
```

**What Happens**:
1. Revocation event created and signed
2. Stored in SQLite (permanent audit log)
3. Cached in Redis (fast lookup)
4. Published to Kafka (propagates to all services)
5. All validation checks will fail for revoked tokens

---

## Complete Client Flow Examples

### Example 1: Simple Login Flow

```python
# 1. Health check
health = requests.get("http://localhost:8000/health").json()

# 2. User login - get access token
token_data = requests.post(
    "http://localhost:8000/token",
    json={"subject": "user123"}
).json()

access_token = token_data["access_token"]

# 3. Use token for API calls
headers = {"Authorization": f"Bearer {access_token}"}
api_response = requests.get("https://api.example.com/data", headers=headers)

# 4. If token expires, user must login again
```

### Example 2: Long-term Session with Refresh

```python
# 1. Login with refresh token
device_id = get_device_fingerprint()
tokens = requests.post(
    "http://localhost:8000/token/refresh/create",
    json={
        "subject": "user123",
        "client_binding": device_id
    }
).json()

# Store securely
save_refresh_token(tokens["refresh_token"])

# 2. Use access token
access_token = tokens["access_token"]

# 3. When access token expires, refresh it
def refresh_if_needed():
    if is_token_expired(access_token):
        new_token = refresh_access_token(
            get_refresh_token(),
            device_id
        )
        return new_token
    return access_token

# 4. Logout
requests.post(
    "http://localhost:8000/token/refresh/revoke",
    json=get_refresh_token()
)
```

### Example 3: Security Incident Response

```python
# User reports account compromised
user_id = "user123"

# 1. Revoke all user tokens immediately
requests.post(
    "http://localhost:8000/revoke",
    json={
        "type": "revoke_sub",
        "value": user_id
    }
)

# 2. Revoke specific refresh token if known
requests.post(
    "http://localhost:8000/token/refresh/revoke",
    json=compromised_refresh_token
)

# 3. Force re-authentication
# User must login again with new credentials
```

---

## Endpoint Summary Table

| # | Method | Endpoint | Purpose | Use Case |
|---|--------|----------|---------|----------|
| 1 | GET | `/` | Service info | Initial connection |
| 2 | GET | `/health` | Health check | Monitoring |
| 3 | POST | `/token` | Create access token | Login |
| 4 | POST | `/token/validate` | Validate token | Security check |
| 5 | GET | `/token/inspect` | Inspect token | Debugging |
| 6 | POST | `/token/refresh/create` | Create refresh token | Long-term session |
| 7 | POST | `/token/refresh` | Refresh token | Token renewal |
| 8 | POST | `/token/refresh/revoke` | Revoke refresh token | Logout |
| 9 | POST | `/revoke` | Revoke token | Security/Logout |

---

## Best Practices for Clients

1. **Always validate tokens** before using them
2. **Store refresh tokens securely** (encrypted storage)
3. **Use same client_binding** for refresh operations
4. **Handle token expiration** gracefully
5. **Revoke tokens on logout** for security
6. **Implement token refresh** before expiration
7. **Use HTTPS** in production
8. **Handle errors** appropriately (401 = re-authenticate)

---

## Error Handling

All endpoints return standard HTTP status codes:
- `200`: Success
- `400`: Bad request (invalid input)
- `401`: Unauthorized (invalid/expired/revoked token)
- `503`: Service unavailable (Redis/Kafka not ready)

Always check response status and handle errors appropriately.

---

For interactive API testing, visit: **http://localhost:8000/docs**

