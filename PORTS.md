<<<<<<< ours
# Quitty Port Map

This file summarizes all service ports across the repository and a safe plan to run everything together without host-port conflicts.

## 1) Current Host Ports

### web-app (`web-app/docker-compose.yml`)

| Service | Host:Container | Notes |
|---|---|---|
| frontend | `3000:3000` | Next.js UI |
| auth | `8001:8001` | Auth API |
| db | `8002:8002` | Cart DB API |
| cart | `8003:8003` | Cart API |
| product | `8004:8004` | Product API |

### ejwks-merkle (`ejwks-merkle/docker-compose.yml`)

| Service | Host:Container | Notes |
|---|---|---|
| ejwks-api | `8000:8000` | JWKS/Merkle API |
| redis | `6379:6379` | Redis for ejwks |

### revocation infra (`revocation/docker-compose.yml`)

| Service | Host:Container | Notes |
|---|---|---|
| redis | `6379:6379` | Redis for revocation |
| zookeeper | `not exposed` | ZK for Kafka (internal only) |
| kafka | `${KAFKA_EXTERNAL_PORT:-29092}:29092` | External Kafka listener |

### Non-compose runtime defaults

| Service | Default Port | Notes |
|---|---|---|
| revocation API | `8400` | `start.sh` / `start.bat` run uvicorn on `8400` |
| ejwks local uvicorn | `8000` | README/quick-start examples |
| guard-service defaults | `8003`/`8001`/`8002` | `REVOCATION_BASE_URL` / `JWKS_BASE_URL` / `SIGNER_BASE_URL` |

## 2) Real Conflicts

1. `6379` collision between `ejwks-merkle` Redis and `revocation` Redis if both compose stacks run at once.
2. `guard-service` default URLs point to ports that overlap web-app services, so they can call the wrong service unless explicitly configured.

## 3) Safe "Run All Together" Port Plan

Keep `web-app` unchanged and remap other stacks:

| Component | Recommended Host Port | Container Port |
|---|---|---|
| web frontend | `3000` | `3000` |
| web auth | `8001` | `8001` |
| web db | `8002` | `8002` |
| web cart | `8003` | `8003` |
| web product | `8004` | `8004` |
| ejwks-api | `8200` | `8000` |
| ejwks redis | `6380` | `6379` |
<<<<<<< Updated upstream
| revocation API | `8300` | `8000` |
=======
| revocation API | `8400` | `8400` |
>>>>>>> Stashed changes
| revocation redis | `6381` | `6379` |
| zookeeper | `2181` | `2181` |
| kafka external | `29092` | `29092` |

## 4) Guard-Service Env (Recommended)

Set these when running `guard-service` with the plan above:

```env
<<<<<<< Updated upstream
REVOCATION_BASE_URL=http://127.0.0.1:8300
JWKS_BASE_URL=http://127.0.0.1:8200
SIGNER_BASE_URL=http://127.0.0.1:8400
=======
REVOCATION_BASE_URL=http://127.0.0.1:8400
JWKS_BASE_URL=http://127.0.0.1:8100
SIGNER_BASE_URL=http://127.0.0.1:8300
>>>>>>> Stashed changes
```

Note: `8400` is only an example for P1 signer. If P1 runs on a different host port, use that value.

## 5) Optional Compose Overrides

Create overrides instead of editing original compose files:

- `ejwks-merkle/docker-compose.override.yml`
- `revocation/docker-compose.override.yml`

Example mappings to apply:

- ejwks: `8200:8000`, `6380:6379`
- revocation infra: `6381:6379` (keep `2181:2181`, `29092:29092`)
<<<<<<< Updated upstream
- revocation API (if containerized later): `8300:8000`
=======
- revocation API (if containerized later): `8400:8400`
>>>>>>> Stashed changes

## 6) Quick Port Check (Windows PowerShell)

```powershell
Get-NetTCPConnection -State Listen |
<<<<<<< Updated upstream
  Where-Object { $_.LocalPort -in 3000,8000,8001,8002,8003,8004,8200,8300,8400,6379,6380,6381,2181,29092 } |
=======
  Where-Object { $_.LocalPort -in 3000,8000,8001,8002,8003,8004,8100,8400,6379,6380,6381,2181,29092 } |
>>>>>>> Stashed changes
  Sort-Object LocalPort |
  Select-Object LocalAddress,LocalPort,OwningProcess
```
=======
# Quitty Port Map

This file summarizes all service ports across the repository and a safe plan to run everything together without host-port conflicts.

## 1) Current Host Ports

### web-app (`web-app/docker-compose.yml`)

| Service | Host:Container | Notes |
|---|---|---|
| frontend | `3000:3000` | Next.js UI |
| auth | `8001:8001` | Auth API |
| db | `8002:8002` | Cart DB API |
| cart | `8003:8003` | Cart API |
| product | `8004:8004` | Product API |

### ejwks-merkle (`ejwks-merkle/docker-compose.yml`)

| Service | Host:Container | Notes |
|---|---|---|
| ejwks-api | `8000:8000` | JWKS/Merkle API |
| redis | `6379:6379` | Redis for ejwks |

### revocation infra (`revocation/docker-compose.yml`)

| Service | Host:Container | Notes |
|---|---|---|
| redis | `6379:6379` | Redis for revocation |
| zookeeper | `not exposed` | ZK for Kafka (internal only) |
| kafka | `${KAFKA_EXTERNAL_PORT:-29092}:29092` | External Kafka listener |

### Non-compose runtime defaults

| Service | Default Port | Notes |
|---|---|---|
| revocation API | `8400` | `start.sh` / `start.bat` run uvicorn on `8400` |
| ejwks local uvicorn | `8000` | README/quick-start examples |
| guard-service defaults | `8003`/`8001`/`8002` | `REVOCATION_BASE_URL` / `JWKS_BASE_URL` / `SIGNER_BASE_URL` |

## 2) Real Conflicts

1. `6379` collision between `ejwks-merkle` Redis and `revocation` Redis if both compose stacks run at once.
2. `guard-service` default URLs point to ports that overlap web-app services, so they can call the wrong service unless explicitly configured.

## 3) Safe "Run All Together" Port Plan

Keep `web-app` unchanged and remap other stacks:

| Component | Recommended Host Port | Container Port |
|---|---|---|
| web frontend | `3000` | `3000` |
| web auth | `8001` | `8001` |
| web db | `8002` | `8002` |
| web cart | `8003` | `8003` |
| web product | `8004` | `8004` |
| ejwks-api | `8200` | `8000` |
| ejwks redis | `6380` | `6379` |
<<<<<<< Updated upstream
| revocation API | `8300` | `8000` |
=======
| revocation API | `8400` | `8400` |
>>>>>>> Stashed changes
| revocation redis | `6381` | `6379` |
| zookeeper | `2181` | `2181` |
| kafka external | `29092` | `29092` |

## 4) Guard-Service Env (Recommended)

Set these when running `guard-service` with the plan above:

```env
<<<<<<< Updated upstream
REVOCATION_BASE_URL=http://127.0.0.1:8300
JWKS_BASE_URL=http://127.0.0.1:8200
SIGNER_BASE_URL=http://127.0.0.1:8400
=======
REVOCATION_BASE_URL=http://127.0.0.1:8400
JWKS_BASE_URL=http://127.0.0.1:8100
SIGNER_BASE_URL=http://127.0.0.1:8300
>>>>>>> Stashed changes
```

Note: `8400` is only an example for P1 signer. If P1 runs on a different host port, use that value.

## 5) Optional Compose Overrides

Create overrides instead of editing original compose files:

- `ejwks-merkle/docker-compose.override.yml`
- `revocation/docker-compose.override.yml`

Example mappings to apply:

- ejwks: `8200:8000`, `6380:6379`
- revocation infra: `6381:6379` (keep `2181:2181`, `29092:29092`)
<<<<<<< Updated upstream
- revocation API (if containerized later): `8300:8000`
=======
- revocation API (if containerized later): `8400:8400`
>>>>>>> Stashed changes

## 6) Quick Port Check (Windows PowerShell)

```powershell
Get-NetTCPConnection -State Listen |
<<<<<<< Updated upstream
  Where-Object { $_.LocalPort -in 3000,8000,8001,8002,8003,8004,8200,8300,8400,6379,6380,6381,2181,29092 } |
=======
  Where-Object { $_.LocalPort -in 3000,8000,8001,8002,8003,8004,8100,8400,6379,6380,6381,2181,29092 } |
>>>>>>> Stashed changes
  Sort-Object LocalPort |
  Select-Object LocalAddress,LocalPort,OwningProcess
```
>>>>>>> theirs
