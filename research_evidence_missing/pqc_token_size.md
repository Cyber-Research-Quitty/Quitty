# PQC Token Size Evidence

## Source
- PQC source artifact: `research_evidence_missing/raw/pqc_token_live_samples.json`
- PQC source measurement timestamp (UTC): `2026-03-21T10:17:29.511964+00:00`
- RS256 reference artifact: `web-app-rsa/benchmark_results_rsa/summary.json`
- Token acquisition path: `POST http://localhost:8001/login`

## Measured facts

| Metric | Value |
| --- | ---: |
| Algorithm | `ml-dsa-44` |
| Sample count | 10 |
| Representative PQC token size | 3551 bytes |
| Representative PQC token length | 3551 characters |
| Average PQC token size | 3551.0 bytes |
| Average PQC token length | 3551.0 characters |
| Minimum PQC token size | 3551 bytes |
| Maximum PQC token size | 3551 bytes |
| RS256 token size reference | 519 bytes |

## Measurement method
- Each sample was obtained from the integrated PQC login path `POST /login`.
- Bytes were measured with `len(token.encode('utf-8'))`.
- Characters were measured with `len(token)`.

## Interpretation
- None beyond the measured values above. This file records the exact PQC token size evidence needed for comparison with the existing RS256 figure.
