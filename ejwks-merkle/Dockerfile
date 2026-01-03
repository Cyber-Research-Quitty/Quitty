# ---------- Base image ----------
FROM python:3.12-slim

# Prevent Python from writing .pyc files and enable unbuffered logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Create app user (non-root)
RUN useradd -m appuser

WORKDIR /app

# System deps: Install build tools and OpenSSL for liboqs (Post-Quantum Cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    build-essential cmake git ninja-build \
    libssl-dev \
  && rm -rf /var/lib/apt/lists/*

# Build and install liboqs from source
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
  && mkdir /tmp/liboqs/build && cd /tmp/liboqs/build \
  && cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON .. \
  && cmake --build . && cmake --install . \
  && ldconfig \
  && rm -rf /tmp/liboqs

# Install Python dependencies (including liboqs-python which will use the installed liboqs)
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
