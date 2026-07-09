FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UVICORN_HOST=0.0.0.0 \
    UVICORN_HTTPS_PORT=443 \
    APP_ENV_FILE=/app/.env \
    LAB_NAME="AI Security Practice Target" \
    LAB_DEFENSE_MODE=monitor \
    LAB_ADMIN_TOKEN=training-admin \
    LAB_COMPAT_API_KEY=training-key \
    LAB_API_RATE_LIMIT=30 \
    LAB_TLS_CERT_FILE=/app/certs/lab.crt \
    LAB_TLS_KEY_FILE=/app/certs/lab.key \
    LAB_TLS_HOSTS=localhost,127.0.0.1,0.0.0.0

WORKDIR /app

RUN mkdir -p /app/certs

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements-docker.txt ./
RUN pip install --no-cache-dir -r requirements-docker.txt

COPY . .

EXPOSE 443

ENTRYPOINT ["python", "/app/docker/entrypoint.py"]
CMD ["python", "/app/docker/run_servers.py"]

# 确保 Python 能发现 src 包
ENV PYTHONPATH=/app/src
