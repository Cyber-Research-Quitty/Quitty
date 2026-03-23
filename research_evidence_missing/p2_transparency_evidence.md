# P2 Transparency Evidence

## Source
- Source artifact: `research_evidence_missing/raw/p2_transparency_live.json`
- Source measurement timestamp (UTC): `2026-03-21T10:13:48.625108+00:00`

## Measured facts

| Item | Value |
| --- | --- |
| Rotated key `kid` | `ratHRWiLKZr8phUlq97JWQ` |
| Published key `jkt` | `rbEzkrLDwbZrgyk7saIaMO2RP1hLSPzQYQSjlVQCwkQ` |
| Published key length | 1312 |
| JWKS root before import | `HtdXH-eT4IGYvgEXGECZMby-Lbz_x7qgO10dQjlCbhI` |
| Checkpoint index before import | 58 |
| Checkpoint entry hash before import | `m8gI9Xhwrej8J2ihbiMmDZuaYCaiIjBlSRyM68f_Ug0` |
| JWKS root after import | `Tm2UduySwXyoUkhjjsZI3hFB5nGc4rbqYcE6nqMPf8c` |
| Checkpoint index after import | 59 |
| Checkpoint `prev_hash` after import | `m8gI9Xhwrej8J2ihbiMmDZuaYCaiIjBlSRyM68f_Ug0` |
| Checkpoint entry hash after import | `U9_6fa8CwAR0gXVInqUDwtbXbWA-0qtXNbnKw7t0egM` |
| Log root after import | `GvOrRcaeQbfonk03g4l9RDMvw7dAt-ThF6tjkA8hjpM` |
| Proof endpoint returned latest checkpoint index | 59 |
| Proof endpoint returned Merkle proof length | 6 |

## Interpretation
- This live run shows key rotation in P1, publication into P2, a new transparency checkpoint (`58 -> 59`), and a proof response for the published key.
- The value of `after checkpoint prev_hash` exactly matches `before checkpoint entry_hash` in the source artifact.
