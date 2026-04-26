FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive
ENV OQS_INSTALL_PATH=/usr/local
ENV LD_LIBRARY_PATH=/usr/local/lib
ENV LIBOQS_VERSION=0.14.0

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        git \
        libssl-dev \
        ninja-build \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --branch ${LIBOQS_VERSION} --depth 1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=${OQS_INSTALL_PATH} \
    && cmake --build /tmp/liboqs/build --parallel 4 \
    && cmake --build /tmp/liboqs/build --target install \
    && ldconfig \
    && rm -rf /tmp/liboqs

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/app
COPY consumer /app/consumer
COPY scripts /app/scripts

# Runtime defaults (can be overridden by docker-compose env).
ENV REDIS_URL=redis://redis:6379/0
ENV KAFKA_BOOTSTRAP=kafka:9092
ENV ACCESS_TOKEN_PROVIDER=p1
ENV P1_SIGN_BASE_URL=http://host.docker.internal:8100
ENV P1_ACCESS_TOKEN_ALG=ml-dsa-44

EXPOSE 8400

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8400"]
