FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    SYSLOG_HOST=0.0.0.0 \
    SYSLOG_PORT=514 \
    SYSLOG_PORTS=514,1514 \
    WEB_HOST=0.0.0.0 \
    WEB_PORT=8321 \
    RETENTION_DAYS=14

WORKDIR /app

# Install system dependencies if required
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY app/ ./app

# Create persistent storage directory
RUN mkdir -p /data/devices

# Expose ports:
# 514/udp & 514/tcp - Standard Syslog
# 1514/udp & 1514/tcp - Alternative / Unprivileged Syslog
# 8321/tcp - Web UI & REST API
EXPOSE 514/udp 514/tcp 1514/udp 1514/tcp 8321/tcp

VOLUME ["/data"]

# Run Uvicorn ASGI server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8321"]
