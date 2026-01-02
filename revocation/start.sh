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

# Wait for services to be ready
echo "Waiting for services to start..."
sleep 5

# Start the API server
echo "Starting API server on http://localhost:8000"
echo "Press Ctrl+C to stop"
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000


