import os
from pathlib import Path
from zoneinfo import ZoneInfo

# Base paths
default_data_dir = "./syslog_data" if os.name == "nt" else "/data"
DATA_DIR = Path(os.getenv("DATA_DIR", default_data_dir)).resolve()
DEVICES_DIR = DATA_DIR / "devices"
REGISTRY_DB_PATH = DATA_DIR / "registry.db"

# Ensure directories exist
DEVICES_DIR.mkdir(parents=True, exist_ok=True)

# Timezone settings (Default: Chișinău Europe/Chisinau)
DEFAULT_TIMEZONE = os.getenv("APP_TIMEZONE", os.getenv("TZ", "Europe/Chisinau"))

def get_app_timezone(tz_name: str = None) -> ZoneInfo:
    """Returns ZoneInfo object, defaulting to Europe/Chisinau."""
    target = tz_name or DEFAULT_TIMEZONE or "Europe/Chisinau"
    try:
        return ZoneInfo(target)
    except Exception:
        return ZoneInfo("Europe/Chisinau")

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
