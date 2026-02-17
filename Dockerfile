FROM python:3.12-slim

LABEL maintainer="Nomotic AI <engineering@nomotic.ai>"
LABEL org.opencontainers.image.source="https://github.com/NomoticAI/nomotic-ci"

# Install git for baseline comparison
RUN apt-get update && apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY entrypoint.py .

ENTRYPOINT ["python", "/app/entrypoint.py"]
