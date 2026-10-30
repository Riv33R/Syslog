import re
import json
import logging
import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import aiosqlite

from app.config import DEVICES_DIR, REGISTRY_DB_PATH, RETENTION_DAYS, get_app_timezone

logger = logging.getLogger("syslog.storage")

# Sanitize IP address to safe filename
def ip_to_filename(ip: str) -> str:
    safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', ip)
    return f"{safe}.db"

def get_device_db_path(ip: str) -> Path:
    return DEVICES_DIR / ip_to_filename(ip)

# Schema definitions
DEVICE_LOGS_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    vendor_type TEXT NOT NULL,
    severity INTEGER NOT NULL,
    facility INTEGER NOT NULL,
    tag TEXT,
    mnemonic TEXT,
    raw TEXT NOT NULL,
    parsed_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity);
CREATE INDEX IF NOT EXISTS idx_logs_facility ON logs(facility);
CREATE INDEX IF NOT EXISTS idx_logs_vendor ON logs(vendor_type);
CREATE INDEX IF NOT EXISTS idx_logs_tag ON logs(tag);
"""

REGISTRY_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS devices (
    ip TEXT PRIMARY KEY,
    db_filename TEXT NOT NULL,
    hostname TEXT,
    vendor_type TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    log_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS webhooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    target_url TEXT NOT NULL,
    vendor TEXT,
    max_severity INTEGER,
    action TEXT,
    filter_regex TEXT,
    enabled INTEGER DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS forwarding_endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    target_type TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER DEFAULT 514,
    filter_source_ip TEXT,
    filter_vendor TEXT,
    filter_max_severity INTEGER,
    forward_format TEXT DEFAULT 'raw',
    enabled INTEGER DEFAULT 1,
    forwarded_count INTEGER DEFAULT 0,
    last_forwarded TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

# Default system settings (Default timezone: Europe/Chisinau)
DEFAULT_SETTINGS = {
    "timezone": "Europe/Chisinau",
    "language": "en",
    "retention_days": "14",
    "date_format": "YYYY-MM-DD HH:mm:ss",
    "autoscroll": "true"
}

# Track initialized DB paths in memory to avoid repetitive CREATE TABLE overhead
_INITIALIZED_DBS = set()
_LOCK = asyncio.Lock()

async def init_registry_db():
    """Initializes the central registry database and ensures default settings exist."""
    now_iso = datetime.now(get_app_timezone()).isoformat()
    async with aiosqlite.connect(REGISTRY_DB_PATH) as db:
        await db.executescript(REGISTRY_SCHEMA)
        # Ensure default settings are populated if missing
        for key, val in DEFAULT_SETTINGS.items():
            await db.execute(
                "INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
                (key, str(val), now_iso)
            )
        await db.commit()
    logger.info("Central registry DB initialized at %s with Europe/Chisinau default timezone", REGISTRY_DB_PATH)

async def ensure_device_db(ip: str) -> Path:
    """
    Ensures the SQLite database and table for the given IP exists in WAL mode.
    Thread-safe and async-safe.
    """
    db_path = get_device_db_path(ip)
    if db_path in _INITIALIZED_DBS and db_path.exists():
        return db_path

    async with _LOCK:
        if db_path in _INITIALIZED_DBS and db_path.exists():
            return db_path

        async with aiosqlite.connect(db_path) as db:
            await db.executescript(DEVICE_LOGS_SCHEMA)
            await db.commit()

        _INITIALIZED_DBS.add(db_path)
        logger.info("Initialized isolated DB for device %s at %s", ip, db_path)
    return db_path

async def _insert_single_device_logs(ip: str, items: List[Dict[str, Any]]):
    """Inserts batch items into a specific device database."""
    db_path = await ensure_device_db(ip)
    rows_to_insert = [
        (
            it["timestamp"],
            it["source_ip"],
            it["vendor_type"],
            it["severity"],
            it["facility"],
            it.get("tag"),
            it.get("mnemonic"),
            it["raw"],
            json.dumps(it["parsed_json"], ensure_ascii=False)
        )
        for it in items
    ]

    try:
        async with aiosqlite.connect(db_path) as db:
            await db.executemany(
                """
                INSERT INTO logs (timestamp, source_ip, vendor_type, severity, facility, tag, mnemonic, raw, parsed_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows_to_insert
            )
            await db.commit()
    except Exception as e:
        logger.error("Failed to insert logs into %s: %s", db_path, e, exc_info=True)

async def insert_logs_batch(batch: List[Dict[str, Any]]):
    """
    High-throughput batch insertion:
    1. Groups logs by source_ip.
    2. Concurrently inserts rows into each isolated per-device database using asyncio.gather.
    3. Updates registry device records (hostname, vendor, log count, last_seen).
    """
    if not batch:
        return

    # Group by source_ip
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for item in batch:
        ip = item["source_ip"]
        grouped.setdefault(ip, []).append(item)

    now_iso = datetime.now(get_app_timezone()).isoformat()

    # 1. Concurrent insert into per-device DBs (zero lock contention across devices)
    insert_tasks = [_insert_single_device_logs(ip, items) for ip, items in grouped.items()]
    await asyncio.gather(*insert_tasks)

    # 2. Update Registry DB
    try:
        async with aiosqlite.connect(REGISTRY_DB_PATH) as reg_db:
            for ip, items in grouped.items():
                count = len(items)
                last_item = items[-1]
                vendor = last_item["vendor_type"]
                hostname = last_item.get("hostname")
                filename = ip_to_filename(ip)

                # Check if device exists
                async with reg_db.execute("SELECT hostname, vendor_type FROM devices WHERE ip = ?", (ip,)) as cursor:
                    row = await cursor.fetchone()

                if row is None:
                    await reg_db.execute(
                        """
                        INSERT INTO devices (ip, db_filename, hostname, vendor_type, first_seen, last_seen, log_count)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (ip, filename, hostname or ip, vendor, now_iso, now_iso, count)
                    )
                else:
                    curr_host, curr_vendor = row
                    new_host = hostname if (hostname and (not curr_host or curr_host == ip)) else curr_host
                    new_vendor = vendor if (curr_vendor == "generic" and vendor != "generic") else curr_vendor

                    await reg_db.execute(
                        """
                        UPDATE devices
                        SET log_count = log_count + ?,
                            last_seen = ?,
                            hostname = ?,
                            vendor_type = ?
                        WHERE ip = ?
                        """,
                        (count, now_iso, new_host, new_vendor, ip)
                    )
            await reg_db.commit()
    except Exception as e:
        logger.error("Failed to update registry DB: %s", e, exc_info=True)

async def get_all_devices() -> List[Dict[str, Any]]:
    """Returns list of all registered devices with online status calculation."""
    devices = []
    now = datetime.now(get_app_timezone())
    online_threshold = timedelta(minutes=5)

    try:
        async with aiosqlite.connect(REGISTRY_DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM devices ORDER BY last_seen DESC") as cursor:
                async for row in cursor:
                    d = dict(row)
                    try:
                        last_seen_dt = datetime.fromisoformat(d["last_seen"])
                        if last_seen_dt.tzinfo is None:
                            last_seen_dt = last_seen_dt.replace(tzinfo=get_app_timezone())
                        d["is_online"] = (now - last_seen_dt) <= online_threshold
                    except Exception:
                        d["is_online"] = False
                    devices.append(d)
    except Exception as e:
        logger.error("Error fetching devices from registry: %s", e)
    return devices

async def get_device_info(ip: str) -> Optional[Dict[str, Any]]:
    """Returns metadata for a specific device."""
    try:
        async with aiosqlite.connect(REGISTRY_DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM devices WHERE ip = ?", (ip,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    return dict(row)
    except Exception as e:
        logger.error("Error fetching device %s: %s", ip, e)
    return None

async def delete_device(ip: str) -> bool:
    """
    Removes a device from registry.db and permanently deletes its isolated SQLite database files.
    """
    db_path = get_device_db_path(ip)
    deleted_from_reg = False

    try:
        async with aiosqlite.connect(REGISTRY_DB_PATH) as db:
            cursor = await db.execute("DELETE FROM devices WHERE ip = ?", (ip,))
            await db.commit()
            deleted_from_reg = cursor.rowcount > 0
    except Exception as e:
        logger.error("Error deleting device %s from registry: %s", ip, e)

    # Delete physical files: .db, -wal, -shm
    for suffix in ["", "-wal", "-shm"]:
        target_file = db_path.with_name(db_path.name + suffix if suffix else db_path.name)
        if target_file.exists():
            try:
                target_file.unlink()
            except Exception as e:
                logger.warning("Could not delete file %s: %s", target_file, e)

    _INITIALIZED_DBS.discard(db_path)
    logger.info("Successfully deleted device %s and its storage", ip)
    return deleted_from_reg or not db_path.exists()

async def purge_synthetic_test_devices() -> List[str]:
    """
    Purges synthetic test devices (10.0.0.x, 192.168.1.1x, 127.0.0.1) from databases.
    """
    devices = await get_all_devices()
    purged: List[str] = []

    for d in devices:
        ip = d["ip"]
        is_test = (
            ip.startswith("10.0.0.") or
            ip.startswith("10.100.") or
            (ip.startswith("192.168.1.") and any(ip == f"192.168.1.{n}" for n in range(10, 20))) or
            ip == "127.0.0.1"
        )
        if is_test:
            await delete_device(ip)
            purged.append(ip)

    logger.info("Purged %d synthetic test devices: %s", len(purged), purged)
    return purged

async def query_device_logs(
    ip: str,
    limit: int = 100,
    offset: int = 0,
    severity: Optional[int] = None,
    severity_max: Optional[int] = None,
    facility: Optional[int] = None,
    vendor_type: Optional[str] = None,
    q: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    tag: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Queries logs from an isolated device database with filtering and pagination.
    Supports severity exact / threshold, facility, vendor, full-text keyword, time range, and tag/mnemonic.
    Returns (logs_list, total_matching_count).
    """
    db_path = get_device_db_path(ip)
    if not db_path.exists():
        return [], 0

    where_clauses = ["1=1"]
    params: List[Any] = []

    if severity is not None:
        where_clauses.append("severity = ?")
        params.append(severity)
    elif severity_max is not None:
        where_clauses.append("severity <= ?")
        params.append(severity_max)

    if facility is not None:
        where_clauses.append("facility = ?")
        params.append(facility)

    if vendor_type and vendor_type.lower() != "all":
        where_clauses.append("vendor_type = ?")
        params.append(vendor_type.lower())

    if tag and tag.strip():
        tag_pattern = f"%{tag.strip()}%"
        where_clauses.append("(tag LIKE ? OR mnemonic LIKE ?)")
        params.extend([tag_pattern, tag_pattern])

    if start_time and start_time.strip():
        where_clauses.append("timestamp >= ?")
        params.append(start_time.strip())

    if end_time and end_time.strip():
        where_clauses.append("timestamp <= ?")
        params.append(end_time.strip())

    if q and q.strip():
        search_pattern = f"%{q.strip()}%"
        where_clauses.append("(raw LIKE ? OR parsed_json LIKE ? OR mnemonic LIKE ? OR tag LIKE ? OR source_ip LIKE ?)")
        params.extend([search_pattern, search_pattern, search_pattern, search_pattern, search_pattern])

    where_sql = " AND ".join(where_clauses)

    logs: List[Dict[str, Any]] = []
    total = 0

    try:
        async with aiosqlite.connect(db_path) as db:
            db.row_factory = aiosqlite.Row

            # Count total
            count_sql = f"SELECT COUNT(*) as cnt FROM logs WHERE {where_sql}"
            async with db.execute(count_sql, params) as cursor:
                row = await cursor.fetchone()
                total = row["cnt"] if row else 0

            # Fetch rows
            fetch_sql = f"""
                SELECT id, timestamp, source_ip, vendor_type, severity, facility, tag, mnemonic, raw, parsed_json
                FROM logs
                WHERE {where_sql}
                ORDER BY timestamp DESC, id DESC
                LIMIT ? OFFSET ?
            """
            fetch_params = params + [limit, offset]
            async with db.execute(fetch_sql, fetch_params) as cursor:
                async for row in cursor:
                    item = dict(row)
                    try:
                        item["parsed_json"] = json.loads(item["parsed_json"])
                    except Exception:
                        pass
                    logs.append(item)
    except Exception as e:
        logger.error("Query failed for device %s: %s", ip, e)

    return logs, total

async def query_all_devices_logs(
    limit: int = 100,
    offset: int = 0,
    severity: Optional[int] = None,
    severity_max: Optional[int] = None,
    facility: Optional[int] = None,
    vendor_type: Optional[str] = None,
    q: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    tag: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    """
    High-performance cross-device query using parallel asyncio.gather across all per-device DBs.
    Aggregates results matching filters, sorted by timestamp descending.
    """
    if not DEVICES_DIR.exists():
        return [], 0

    db_files = list(DEVICES_DIR.glob("*.db"))
    if not db_files:
        return [], 0

    per_db_fetch_limit = offset + limit

    tasks = [
        query_device_logs(
            ip=db_file.stem,
            limit=per_db_fetch_limit,
            offset=0,
            severity=severity,
            severity_max=severity_max,
            facility=facility,
            vendor_type=vendor_type,
            q=q,
            start_time=start_time,
            end_time=end_time,
            tag=tag,
        )
        for db_file in db_files
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    aggregated_logs: List[Dict[str, Any]] = []
    total_count = 0

    for res in results:
        if isinstance(res, tuple):
            dev_logs, dev_total = res
            total_count += dev_total
            aggregated_logs.extend(dev_logs)
        elif isinstance(res, Exception):
            logger.error("Error querying device log partition: %s", res)

    # Sort aggregated logs by timestamp DESC, id DESC
    aggregated_logs.sort(key=lambda x: (x.get("timestamp", ""), x.get("id", 0)), reverse=True)

    # Apply pagination slice
    paginated = aggregated_logs[offset : offset + limit]
    return paginated, total_count

async def cleanup_retention_worker(retention_days: int = RETENTION_DAYS):
    """
    Background retention worker.
    Scans all per-device DBs and purges records older than retention_days.
    """
    cutoff = (datetime.now(get_app_timezone()) - timedelta(days=retention_days)).isoformat()
    logger.info("Running retention cleanup for logs older than %d days (cutoff: %s)", retention_days, cutoff)

    if not DEVICES_DIR.exists():
        return

    db_files = list(DEVICES_DIR.glob("*.db"))
    for db_path in db_files:
        try:
            async with aiosqlite.connect(db_path) as db:
                await db.execute("DELETE FROM logs WHERE timestamp < ?", (cutoff,))
                await db.commit()
                # Run lightweight WAL checkpoint
                await db.execute("PRAGMA wal_checkpoint(PASSIVE);")
        except Exception as e:
            logger.error("Retention purge error on %s: %s", db_path, e)

    # Recalculate device log counts in registry
    try:
        async with aiosqlite.connect(REGISTRY_DB_PATH) as reg_db:
            reg_db.row_factory = aiosqlite.Row
            async with reg_db.execute("SELECT ip, db_filename FROM devices") as cursor:
                devices = await cursor.fetchall()

            for dev in devices:
                dev_db = DEVICES_DIR / dev["db_filename"]
                if dev_db.exists():
                    try:
                        async with aiosqlite.connect(dev_db) as db:
                            async with db.execute("SELECT COUNT(*) FROM logs") as cnt_cur:
                                (count,) = await cnt_cur.fetchone()
                        await reg_db.execute("UPDATE devices SET log_count = ? WHERE ip = ?", (count, dev["ip"]))
                    except Exception:
                        pass
            await reg_db.commit()
            logger.info("Retention cleanup completed successfully.")
    except Exception as e:
        logger.error("Failed to update registry log counts after retention cleanup: %s", e)

# --- Settings & Persistence Management ---

async def get_all_settings() -> Dict[str, str]:
    """Returns dictionary of all system settings with default fallbacks."""
    res = dict(DEFAULT_SETTINGS)
    try:
        async with aiosqlite.connect(REGISTRY_DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT key, value FROM settings") as cursor:
                async for row in cursor:
                    res[row["key"]] = row["value"]
    except Exception as e:
        logger.error("Failed to load settings: %s", e)
    return res

async def get_setting(key: str, default: Optional[str] = None) -> Optional[str]:
    """Gets single setting value."""
    settings = await get_all_settings()
    return settings.get(key, default)

async def update_settings(updates: Dict[str, Any]) -> Dict[str, str]:
    """Updates settings in the persistent registry database."""
    now_str = datetime.now(get_app_timezone()).isoformat()
    async with aiosqlite.connect(REGISTRY_DB_PATH) as db:
        for k, v in updates.items():
            val_str = str(v)
            await db.execute("""
                INSERT INTO settings (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """, (k, val_str, now_str))
        await db.commit()
    return await get_all_settings()

async def export_full_backup() -> Dict[str, Any]:
    """
    Exports all persistent settings, webhooks, forwarding endpoints,
    and device metadata into a portable JSON structure for disaster recovery.
    """
    from app.forwarder import get_all_forwarding_endpoints
    from app.webhooks import get_all_webhooks

    backup = {
        "format": "syslog_aggregator_backup",
        "version": "1.0",
        "exported_at": datetime.now(get_app_timezone()).isoformat(),
        "timezone": await get_setting("timezone", "Europe/Chisinau"),
        "settings": await get_all_settings(),
        "forwarding_endpoints": await get_all_forwarding_endpoints(),
        "webhooks": await get_all_webhooks(),
        "devices": await get_all_devices()
    }
    return backup

async def import_full_backup(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Restores settings, webhooks, and forwarding endpoints from a backup dictionary.
    """
    results = {"settings_imported": 0, "endpoints_imported": 0, "webhooks_imported": 0}
    now_str = datetime.now(get_app_timezone()).isoformat()

    # Import settings
    if "settings" in data and isinstance(data["settings"], dict):
        await update_settings(data["settings"])
        results["settings_imported"] = len(data["settings"])

    async with aiosqlite.connect(REGISTRY_DB_PATH) as db:
        # Import forwarding endpoints
        if "forwarding_endpoints" in data and isinstance(data["forwarding_endpoints"], list):
            for ep in data["forwarding_endpoints"]:
                await db.execute("""
                    INSERT INTO forwarding_endpoints 
                    (name, target_type, host, port, filter_source_ip, filter_vendor, filter_max_severity, forward_format, enabled, forwarded_count, last_forwarded, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ep.get("name", "Restored Endpoint"),
                    ep.get("target_type", "udp"),
                    ep.get("host", "127.0.0.1"),
                    ep.get("port", 514),
                    ep.get("filter_source_ip"),
                    ep.get("filter_vendor"),
                    ep.get("filter_max_severity"),
                    ep.get("forward_format", "raw"),
                    ep.get("enabled", 1),
                    ep.get("forwarded_count", 0),
                    ep.get("last_forwarded"),
                    ep.get("created_at", now_str)
                ))
                results["endpoints_imported"] += 1

        # Import webhooks
        if "webhooks" in data and isinstance(data["webhooks"], list):
            for wh in data["webhooks"]:
                await db.execute("""
                    INSERT INTO webhooks (name, target_url, vendor, max_severity, action, filter_regex, enabled, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    wh.get("name", "Restored Webhook"),
                    wh.get("target_url"),
                    wh.get("vendor"),
                    wh.get("max_severity"),
                    wh.get("action"),
                    wh.get("filter_regex"),
                    wh.get("enabled", 1),
                    wh.get("created_at", now_str)
                ))
                results["webhooks_imported"] += 1

        await db.commit()
    return results
