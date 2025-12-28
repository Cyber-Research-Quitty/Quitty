# ---------- Base image ----------
    FROM python:3.12-slim

    # Prevent Python from writing .pyc files and enable unbuffered logs
    ENV PYTHONDONTWRITEBYTECODE=1 \
        PYTHONUNBUFFERED=1
    
    # Create app user (non-root)
    RUN useradd -m appuser
    
    WORKDIR /app
    
    # System deps (cryptography wheels usually work without build deps on slim,
    # but keeping minimal CA certs and curl helps debugging)
    RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
      && rm -rf /var/lib/apt/lists/*
    
    # Install dependencies first (better caching)
    COPY requirements.txt /app/requirements.txt
    RUN pip install --no-cache-dir -r /app/requirements.txt
    
    # Copy your code
    COPY app/ /app/app/
    COPY client_verify.py /app/client_verify.py
    
    # Create a persistent data directory (will be mounted in K8s)
    RUN mkdir -p /data && chown -R appuser:appuser /data
    
    USER appuser
    
    EXPOSE 8000
    
    # Production run (no reload)
    CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
    