# P4 Revocation Evidence

## Source
- Source artifact: `research_evidence_missing/raw/p4_revocation_live.json`
- Source measurement timestamp (UTC): `2026-03-21T10:17:29.693893+00:00`

## Measured facts

| Item | Value |
| --- | --- |
| Algorithm | `ml-dsa-44` |
| `kid` | `ratHRWiLKZr8phUlq97JWQ` |
| `jti` | `7e9ca828-3940-4e66-ad91-60e8caf7758d` |
| `sub` | `1` |
| Token issue status | 200 |
| `/me` before revoke | 200 |
| P4 token metadata before revoke | `found=true`, `revoked=false` |
| `/logout` revoke status | 200 |
| `/logout` revoke body | `revoked=true`, `jti=7e9ca828-3940-4e66-ad91-60e8caf7758d` |
| P4 token metadata after revoke | `found=true`, `revoked=true`, `revocation_reason=jti` |
| `/me` after revoke | 401 |

## Interpretation
- This live run shows the full P4 revocation path: token issuance, successful use before revocation, revocation by `jti`, metadata update in P4, and rejection of the same token after revocation.
