# PQC Benchmark Artifact

## Source
- Source artifact: `research_evidence_missing/raw/pqc_benchmark_live.json`
- Source measurement timestamp (UTC): `2026-03-21T10:17:28.917982+00:00`
- Measured system path: `POST /login`, `GET /me`, `GET /cart`, `POST /logout` on the integrated PQC web-app

## Measured facts

| Metric | Value |
| --- | ---: |
| VUs | 5 |
| Iterations per VU | 10 |
| Total iterations | 50 |
| Total requests | 200 |
| Login latency (avg) | 83.481 ms |
| Login latency (p95) | 102.453 ms |
| `/me` latency (avg) | 43.448 ms |
| `/me` latency (p95) | 57.907 ms |
| `/cart` latency (avg) | 72.673 ms |
| `/cart` latency (p95) | 101.620 ms |
| `/logout` latency (avg) | 69.378 ms |
| `/logout` latency (p95) | 89.872 ms |
| Overall request latency (avg) | 67.245 ms |
| Overall request latency (p95) | 97.667 ms |
| Overall iteration latency (avg) | 269.401 ms |
| Overall iteration latency (p95) | 334.455 ms |
| Throughput | 71.943 requests/s |
| Failure rate | 0.0 |
| Successful requests | 200 |
| Failed requests | 0 |
| Wall-clock benchmark time | 2.780 s |

## Interpretation
- None beyond the measured values above. This file is a paper-ready extraction of `research_evidence_missing/raw/pqc_benchmark_live.json`.
