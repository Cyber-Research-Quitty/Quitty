FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Build/runtime deps for liboqs-python with ML-DSA verification.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    build-essential cmake git ninja-build \
    libssl-dev \
  && rm -rf /var/lib/apt/lists/*

# Build and install shared liboqs so python-oqs can load it.
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
  && mkdir /tmp/liboqs/build && cd /tmp/liboqs/build \
  && cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON .. \
  && cmake --build . && cmake --install . \
  && ldconfig \
  && rm -rf /tmp/liboqs

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/app
COPY client-verify /app/client-verify

ENV CLIENT_VERIFY_P2_BASE_URL=http://host.docker.internal:8200
ENV CLIENT_VERIFY_KEY_FILE=/app/root_signer_key.json
ENV CLIENT_VERIFY_PINNED_PUB=

EXPOSE 8201

WORKDIR /app/client-verify
CMD ["uvicorn", "client_verify_service:app", "--host", "0.0.0.0", "--port", "8201"]
