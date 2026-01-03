@echo off
REM Startup script for Windows

echo Starting P4 Revocation Service...

REM Check if virtual environment exists
if not exist ".venv" (
    echo Creating virtual environment...
    python -m venv .venv
)

REM Activate virtual environment
call .venv\Scripts\activate.bat

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt

REM Start Docker services
echo Starting Docker services (Redis ^& Kafka)...
docker-compose up -d

REM Wait for services to be ready
echo Waiting for services to start...
timeout /t 5 /nobreak >nul

REM Start the API server
echo Starting API server on http://localhost:8000
echo Press Ctrl+C to stop
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000


