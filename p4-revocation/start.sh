#!/bin/bash
# Startup script for Linux/Mac

echo "Starting P4 Revocation Service..."

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment
source .venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Start Docker services
echo "Starting Docker services (Redis & Kafka)..."
docker-compose up -d
if [ $? -ne 0 ]; then
    echo "ERROR: Docker services failed to start."
    echo "If Kafka port 29092 is busy, set KAFKA_EXTERNAL_PORT first:"
    echo "  export KAFKA_EXTERNAL_PORT=39092"
    echo "and use:"
    echo "  export KAFKA_BOOTSTRAP=localhost:39092"
    exit 1
fi

if [ -n "${KAFKA_EXTERNAL_PORT:-}" ] && [ -z "${KAFKA_BOOTSTRAP:-}" ]; then
    export KAFKA_BOOTSTRAP="localhost:${KAFKA_EXTERNAL_PORT}"
fi

# Wait for services to be ready
echo "Waiting for services to start..."
sleep 8

# Start the API server
echo "Starting API server on http://localhost:8400"
echo "Press Ctrl+C to stop"
uvicorn app.main:app --reload --host 0.0.0.0 --port 8400
