FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY scripts/ /app/scripts/
COPY examples/ /app/examples/

RUN chmod +x /app/scripts/security-node-controller.py /app/scripts/validate-config.py

CMD ["python", "/app/scripts/security-node-controller.py", "--config", "/app/config/config.yaml", "--output", "/app/html/index.html"]
