# P4 Enhanced Secure Revocation (SQLite + Redis + Kafka)

## What it does
- `/revoke` creates a PQC-signed revocation event
- Event is stored in `revocation.db` (SQLite audit log)
- Redis is updated for fast revocation checks
- Kafka broadcasts the event so other services update their Redis too

## Install
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/Mac: source .venv/bin/activate
pip install -r requirements.txt
