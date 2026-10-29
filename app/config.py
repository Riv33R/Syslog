import os
from pathlib import Path

# Base paths
default_data_dir = "./syslog_data" if os.name == "nt" else "/data"
DATA_DIR = Path(os.getenv("DATA_DIR", default_data_dir)).resolve()
DEVICES_DIR = DATA_DIR / "devices"
REGISTRY_DB_PATH = DATA_DIR / "registry.db"

# Ensure directories exist
DEVICES_DIR.mkdir(parents=True, exist_ok=True)

# Network settings
SYSLOG_HOST = os.getenv("SYSLOG_HOST", "0.0.0.0")
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "514"))
# Support listening on multiple ports simultaneously (default: standard 514 and secondary 1514)
SYSLOG_PORTS_STR = os.getenv("SYSLOG_PORTS", "514,1514")
SYSLOG_PORTS = list(dict.fromkeys([int(p.strip()) for p in SYSLOG_PORTS_STR.split(",") if p.strip()] + [SYSLOG_PORT]))

WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.getenv("WEB_PORT", "8321"))

# Retention
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "14"))
CLEANUP_INTERVAL_HOURS = int(os.getenv("CLEANUP_INTERVAL_HOURS", "1"))

# Ingestion batching
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "100"))
BATCH_TIMEOUT_SEC = float(os.getenv("BATCH_TIMEOUT_SEC", "0.25"))
MAX_QUEUE_SIZE = int(os.getenv("MAX_QUEUE_SIZE", "50000"))
