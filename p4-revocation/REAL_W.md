# P4 Real-World Scenario: Quitty Session Revocation

This scenario shows the complete P4 implementation in a realistic e-commerce flow. Quitty users sign in, browse products, add items to a cart, refresh sessions on trusted devices, and can have access removed immediately after logout, device theft, account takeover, or signing-key compromise.

## Scenario

Alice logs in to Quitty from her laptop and receives a short-lived access token plus a long-lived refresh token. The access token lets her call protected product and cart APIs. Later, Alice reports that her laptop was stolen while the browser session was still active.

The system must stop the stolen access token immediately, prevent the refresh token from minting new sessions, preserve an audit record, and make P3 reject the revoked token on the next protected API call.

## Services Involved

| Service | Role in the scenario |
| --- | --- |
| P1 Sign Service | Issues and verifies ML-DSA access tokens. |
| P2 E-JWKS Merkle | Publishes signing-key transparency evidence. |
| P3 Guard Service | Protects product/cart APIs and checks P4 before allowing requests. |
| P4 Revocation | Stores revocation state, signs revocation events, rotates refresh tokens, and exposes lookup APIs. |
| Web Auth Service | Login/logout/session UI integration for Quitty. |
| Cart/Product Services | Real protected resources that rely on P3 validation. |

## Implementation Map

| Requirement | Current implementation |
| --- | --- |
| Revoke one stolen access token | `POST /revoke` with `{"type":"revoke_jti","value":"<jti>"}` |
| Revoke every token for a user | `POST /revoke` with `{"type":"revoke_sub","value":"<sub>"}` |
| Revoke every token signed by a compromised key | `POST /revoke` with `{"type":"revoke_kid","value":"<kid>"}` |
| Verify a token before revoking identifiers from it | `POST /revoke/token` |
| Fast online revocation check | Redis keys such as `revoked:jti:<jti>` |
| Durable audit trail | SQLite `revocation_events`, `refresh_tokens`, and `token_events` tables |
| Event propagation | Kafka `revocations` and `token-events` topics |
| P3-compatible lookup | `GET /v1/revocations/{jti}` |
| Multi-identifier lookup | `POST /v1/revocations/check` with `jti`, `sub`, and/or `kid` |
| P1 token metadata in P4 | `POST /v1/tokens/sync` and `GET /v1/tokens/{jti}` |
| Refresh-token session creation | `POST /token/refresh/create` |
| Refresh-token rotation | `POST /token/refresh` |
| Refresh-token invalidation | `POST /token/refresh/revoke` |

## End-to-End Flow

### 1. Start The Stack

From the repo root:

```powershell
docker compose -f p2-ejwks-merkle/docker-compose.yml up -d
docker compose -f p4-revocation/docker-compose.yml up -d
docker compose -f p1-sign-service/docker-compose.yml up -d
docker compose -f p3-guard-service/docker-compose.yml up -d
docker compose -f web-app/docker-compose.yml up -d
```

Expected local ports:

| Component | URL |
| --- | --- |
| P1 | `http://localhost:8100` |
| P2 | `http://localhost:8200` |
| P3 | `http://localhost:8300` |
| P4 | `http://localhost:8400` |
| Auth API | `http://localhost:8001` |
| Cart API | `http://localhost:8003` |
| Product API | `http://localhost:8004` |
| Frontend | `http://localhost:3050` |

### 2. Alice Logs In

The web auth service signs Alice in through P1 and returns a bearer token:

```powershell
$login = Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:8001/login" `
  -ContentType "application/json" `
  -Body '{"email":"alice@example.com","password":"password123"}'

$token = $login.access_token
$headers = @{ Authorization = "Bearer $token" }
```

Implementation details:

- `web-app/auth/app/main.py` creates claims with `sub`, `email`, `role`, `iss`, `iat`, `exp`, and `jti`.
- P1 signs the token using `ml-dsa-44`.
- P1 can sync token metadata into P4 through `P4_TOKEN_SYNC_URL`.
- P4 stores token metadata under `token:meta:<jti>` so the UI and admin flows can show whether the session is active or revoked.

### 3. Alice Uses Protected APIs

Product and cart calls include the bearer token:

```powershell
Invoke-RestMethod -Method Get -Uri "http://localhost:8004/products" -Headers $headers

Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:8003/cart" `
  -Headers $headers `
  -ContentType "application/json" `
  -Body '{"product_id":"desk-lamp","quantity":1}'
```

Implementation details:

- Product/cart services forward the token to P3.
- P3 verifies the JOSE structure, fetches P2 key evidence, asks P1 to verify the signature, and asks P4 whether the token identifiers are revoked.
- P4 checks `jti`, `sub`, and `kid` using Redis-backed revocation state.
- If no revocation exists, P3 returns valid claims and the resource API proceeds.

### 4. Alice Reports A Stolen Laptop

For a single stolen browser session, revoke only the current access token `jti`.

Using the web app logout path:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8001/logout" -Headers $headers
```

Or use the direct P4 path instead. In this path, capture the session details before revoking the token:

```powershell
$session = Invoke-RestMethod -Method Get -Uri "http://localhost:8001/session/details" -Headers $headers
$jti = $session.token.jti

Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:8400/revoke" `
  -ContentType "application/json" `
  -Body "{`"type`":`"revoke_jti`",`"value`":`"$jti`"}"
```

What P4 does internally:

1. Builds a revocation event with `event_id`, `type`, `value`, timestamp, nonce, and P4 signing `kid`.
2. Signs the canonical event using ML-DSA through `dilithium_sign`.
3. Inserts the event into SQLite `revocation_events`.
4. Writes `revoked:jti:<jti>` to Redis for fast checks.
5. Publishes the signed event to Kafka so consumers can update local state.

### 5. The Stolen Token Is Rejected

The same token now fails on the next protected call:

```powershell
Invoke-RestMethod -Method Get -Uri "http://localhost:8003/cart" -Headers $headers
```

Expected result:

- P3 calls P4.
- P4 returns `revoked=true`.
- P3 rejects the request with `401`.
- Cart/product APIs never receive trusted user claims.

You can inspect P4 directly:

```powershell
Invoke-RestMethod -Method Get -Uri "http://localhost:8400/v1/revocations/$jti"
Invoke-RestMethod -Method Get -Uri "http://localhost:8400/v1/tokens/$jti"
```

### 6. Account Takeover Response

If Alice's account password is compromised, revoking only one `jti` is not enough because the attacker may have several active sessions. Revoke by subject:

```powershell
$sub = $session.token.sub

Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:8400/revoke" `
  -ContentType "application/json" `
  -Body "{`"type`":`"revoke_sub`",`"value`":`"$sub`"}"
```

Effect:

- Every current and future token with `sub=<Alice>` is rejected until the revocation entry expires or is administratively cleared.
- This is the right response for password reset, fraud investigation, or user account suspension.

### 7. Signing-Key Compromise Response

If a P1 signing key is compromised, revoke by `kid`:

```powershell
$kid = $session.token.kid

Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:8400/revoke" `
  -ContentType "application/json" `
  -Body "{`"type`":`"revoke_kid`",`"value`":`"$kid`"}"
```

Effect:

- Every token signed by that key is rejected even if its signature still verifies.
- P1/P2 can rotate keys, while P4 gives immediate enforcement during the incident window.

### 8. Refresh Token Flow For Trusted Devices

For mobile or long-lived browser sessions, P4 can issue a refresh token bound to a device fingerprint:

```powershell
$refreshSession = Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:8400/token/refresh/create" `
  -ContentType "application/json" `
  -Body '{"subject":"alice","client_binding":"alice-laptop-fingerprint","additional_claims":{"role":"member"}}'
```

When the client refreshes:

- The old refresh token is marked revoked.
- A new refresh token is issued.
- A new P1-signed access token is issued.
- The response payload is protected with ML-KEM derived key material and AES-256-GCM.
- Reusing the old refresh token fails because `revoked:jti:<old_refresh_jti>` exists and the refresh cache entry has been deleted.

If the laptop is stolen, revoke the refresh token:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:8400/token/refresh/revoke" `
  -ContentType "application/json" `
  -Body (@{ refresh_token = $refreshSession.refresh_token } | ConvertTo-Json)
```

### 9. Evidence And Audit Trail

P4 keeps two layers of evidence:

| Evidence | Purpose |
| --- | --- |
| Redis revocation keys | Fast online authorization decisions. |
| SQLite `revocation_events` | Durable proof of who/what was revoked and when. |
| SQLite `refresh_tokens` | Refresh-token lifecycle audit. |
| SQLite `token_events` | Creation, rotation, and revocation event history. |
| Kafka events | Propagate revocation and token lifecycle changes to other services. |
| P4 event signature | Tamper-evident revocation record. |

The existing live run `integration-realworld-multi-active-p1-p4.json` demonstrates a larger real-world load case:

- 100 access tokens issued concurrently.
- P3 and P4 both accepted all tokens before revocation.
- Mixed revocation was applied by `jti`, `sub`, and `kid`.
- Post-revocation consistency checked 100 tokens with zero mismatches.
- 25 refresh-token create/rotate flows completed.

## Why This Is A Real Implementation

This is not only a blacklist endpoint. P4 provides the full revocation control plane:

- It accepts security events from auth, admin, and incident-response workflows.
- It supports token-level, user-level, and key-level blast radius.
- It performs fast checks through Redis while keeping durable SQLite audit evidence.
- It publishes signed revocation events for distributed services.
- It integrates with P3 so protected APIs reject revoked sessions before business logic runs.
- It handles refresh-token rotation and stolen-device revocation.
- It is wired into the Quitty web app through login, logout, session details, cart, and product flows.
