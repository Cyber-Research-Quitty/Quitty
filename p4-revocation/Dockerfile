FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/app
COPY consumer /app/consumer

# Runtime defaults (can be overridden by docker-compose env).
ENV REDIS_URL=redis://redis:6379/0
ENV KAFKA_BOOTSTRAP=kafka:9092
ENV ACCESS_TOKEN_PROVIDER=p1
ENV P1_SIGN_BASE_URL=http://host.docker.internal:8100
ENV P1_ACCESS_TOKEN_ALG=ml-dsa-44

EXPOSE 8400

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8400"]
