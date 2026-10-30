FROM python:3.11-slim

# Prevent Python from writing .pyc files, enable unbuffered output, and configure default timezone to Chișinău
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=Europe/Chisinau \
    APP_TIMEZONE=Europe/Chisinau \
    DATA_DIR=/data \
    SYSLOG_HOST=0.0.0.0 \
    SYSLOG_PORT=514 \
    SYSLOG_PORTS=514,1514 \
    WEB_HOST=0.0.0.0 \
    WEB_PORT=8321 \
    RETENTION_DAYS=14

WORKDIR /app

# Install system dependencies including tzdata for accurate Chișinău time
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tzdata \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY app/ ./app

# Create persistent storage directory
RUN mkdir -p /data/devices

VOLUME ["/data"]

# Expose ports:
# 514/udp & 514/tcp - Standard Syslog
# 1514/udp & 1514/tcp - Alternative / Unprivileged Syslog
# 8321/tcp - Web UI & REST API
EXPOSE 514/udp 514/tcp 1514/udp 1514/tcp 8321/tcp

# Run Uvicorn ASGI server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8321"]
