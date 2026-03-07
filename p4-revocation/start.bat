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
if errorlevel 1 (
    echo ERROR: Docker services failed to start.
    echo If Kafka port 29092 is busy, set KAFKA_EXTERNAL_PORT first:
    echo     set KAFKA_EXTERNAL_PORT=39092
    echo and use:
    echo     set KAFKA_BOOTSTRAP=localhost:39092
    exit /b 1
)

if defined KAFKA_EXTERNAL_PORT (
    if not defined KAFKA_BOOTSTRAP (
        set KAFKA_BOOTSTRAP=localhost:%KAFKA_EXTERNAL_PORT%
    )
)

REM Wait for services to be ready
echo Waiting for services to start...
timeout /t 8 /nobreak >nul

REM Start the API server
echo Starting API server on http://localhost:8400
echo Press Ctrl+C to stop
uvicorn app.main:app --reload --host 0.0.0.0 --port 8400


