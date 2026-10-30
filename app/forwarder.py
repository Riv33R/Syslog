import json
import socket
import logging
import asyncio
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import httpx
import aiosqlite

from app.config import REGISTRY_DB_PATH, get_app_timezone
from app.webhooks import get_http_client

logger = logging.getLogger("syslog.forwarder")

# Shared UDP socket for sending syslog packets to remote targets
_UDP_SOCK = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
_UDP_SOCK.setblocking(False)

# In-memory stats counter to avoid locking registry DB on every single log
_FORWARD_STATS: Dict[int, int] = {}
_LAST_FORWARD_TIME: Dict[int, str] = {}


# --- Database Operations ---

async def get_all_forwarding_endpoints() -> List[Dict[str, Any]]:
    endpoints = []
    try:
        async with aiosqlite.connect(REGISTRY_DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM forwarding_endpoints ORDER BY id ASC") as cursor:
                async for row in cursor:
                    ep = dict(row)
                    # Merge live in-memory stats
                    ep_id = ep["id"]
                    if ep_id in _FORWARD_STATS:
                        ep["forwarded_count"] = ep.get("forwarded_count", 0) + _FORWARD_STATS[ep_id]
                    if ep_id in _LAST_FORWARD_TIME:
                        ep["last_forwarded"] = _LAST_FORWARD_TIME[ep_id]
                    endpoints.append(ep)
    except Exception as e:
        logger.error("Error loading forwarding endpoints: %s", e)
    return endpoints


async def create_forwarding_endpoint(
    name: str,
    target_type: str,
    host: str,
    port: int = 514,
    filter_source_ip: Optional[str] = None,
    filter_vendor: Optional[str] = None,
    filter_max_severity: Optional[int] = None,
    forward_format: str = "raw",
    enabled: bool = True
) -> int:
    now_iso = datetime.now(get_app_timezone()).isoformat()
    clean_ip = filter_source_ip.strip() if filter_source_ip and filter_source_ip.strip() else None
    clean_vendor = filter_vendor.strip().lower() if filter_vendor and filter_vendor.strip() else None

    async with aiosqlite.connect(REGISTRY_DB_PATH) as db:
        cursor = await db.execute(
            """
            INSERT INTO forwarding_endpoints
                (name, target_type, host, port, filter_source_ip, filter_vendor, filter_max_severity, forward_format, enabled, forwarded_count, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
            """,
            (
                name.strip(),
                target_type.strip(),
                host.strip(),
                int(port),
                clean_ip,
                clean_vendor,
                filter_max_severity,
                forward_format.strip(),
                1 if enabled else 0,
                now_iso
            )
        )
        await db.commit()
        logger.info("Created forwarding endpoint [%s] -> %s:%d (%s)", name, host, port, target_type)
        return cursor.lastrowid


async def update_forwarding_endpoint(
    endpoint_id: int,
    name: str,
    target_type: str,
    host: str,
    port: int = 514,
    filter_source_ip: Optional[str] = None,
    filter_vendor: Optional[str] = None,
    filter_max_severity: Optional[int] = None,
    forward_format: str = "raw",
    enabled: bool = True
) -> bool:
    clean_ip = filter_source_ip.strip() if filter_source_ip and filter_source_ip.strip() else None
    clean_vendor = filter_vendor.strip().lower() if filter_vendor and filter_vendor.strip() else None

    async with aiosqlite.connect(REGISTRY_DB_PATH) as db:
        cursor = await db.execute(
            """
            UPDATE forwarding_endpoints
            SET name = ?, target_type = ?, host = ?, port = ?,
                filter_source_ip = ?, filter_vendor = ?, filter_max_severity = ?,
                forward_format = ?, enabled = ?
            WHERE id = ?
            """,
            (
                name.strip(),
                target_type.strip(),
                host.strip(),
                int(port),
                clean_ip,
                clean_vendor,
                filter_max_severity,
                forward_format.strip(),
                1 if enabled else 0,
                endpoint_id
            )
        )
        await db.commit()
        return cursor.rowcount > 0


async def delete_forwarding_endpoint(endpoint_id: int) -> bool:
    async with aiosqlite.connect(REGISTRY_DB_PATH) as db:
        cursor = await db.execute("DELETE FROM forwarding_endpoints WHERE id = ?", (endpoint_id,))
        await db.commit()
        _FORWARD_STATS.pop(endpoint_id, None)
        _LAST_FORWARD_TIME.pop(endpoint_id, None)
        return cursor.rowcount > 0


async def toggle_forwarding_endpoint(endpoint_id: int, enabled: bool) -> bool:
    async with aiosqlite.connect(REGISTRY_DB_PATH) as db:
        cursor = await db.execute(
            "UPDATE forwarding_endpoints SET enabled = ? WHERE id = ?",
            (1 if enabled else 0, endpoint_id)
        )
        await db.commit()
        return cursor.rowcount > 0


async def flush_forwarding_stats():
    """Periodically flushes accumulated in-memory stats to registry DB."""
    if not _FORWARD_STATS:
        return
    try:
        async with aiosqlite.connect(REGISTRY_DB_PATH) as db:
            for ep_id, count in list(_FORWARD_STATS.items()):
                last_time = _LAST_FORWARD_TIME.get(ep_id)
                await db.execute(
                    """
                    UPDATE forwarding_endpoints
                    SET forwarded_count = forwarded_count + ?,
                        last_forwarded = COALESCE(?, last_forwarded)
                    WHERE id = ?
                    """,
                    (count, last_time, ep_id)
                )
                _FORWARD_STATS[ep_id] = 0
            await db.commit()
    except Exception as e:
        logger.error("Failed to flush forwarding stats: %s", e)


# --- Forwarding Dispatch Logic ---

def matches_endpoint(log_item: Dict[str, Any], ep: Dict[str, Any]) -> bool:
    """Checks whether a parsed syslog entry satisfies the endpoint forwarding filters."""
    if not ep.get("enabled", 1):
        return False

    # 1. Source Device IP Filter
    filter_ip = ep.get("filter_source_ip")
    if filter_ip and filter_ip.strip():
        if log_item.get("source_ip") != filter_ip.strip():
            return False

    # 2. Vendor Filter
    filter_vendor = ep.get("filter_vendor")
    if filter_vendor and filter_vendor.strip() and filter_vendor.lower() != "all":
        if log_item.get("vendor_type", "").lower() != filter_vendor.strip().lower():
            return False

    # 3. Severity Filter (Syslog severity <= filter_max_severity)
    max_sev = ep.get("filter_max_severity")
    if max_sev is not None and max_sev != "":
        if log_item.get("severity", 999) > int(max_sev):
            return False

    return True


async def dispatch_to_endpoint(ep: Dict[str, Any], log_item: Dict[str, Any]):
    """Asynchronously forwards a log message to the specified endpoint."""
    target_type = ep.get("target_type", "syslog_udp")
    host = ep.get("host")
    port = int(ep.get("port", 514))
    fmt = ep.get("forward_format", "raw")
    ep_id = ep["id"]

    try:
        # 1. Syslog over UDP
        if target_type == "syslog_udp":
            if fmt == "json":
                payload = json.dumps(log_item.get("parsed_json", {}), ensure_ascii=False).encode("utf-8")
            else:
                payload = log_item.get("raw", "").encode("utf-8")

            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, _UDP_SOCK.sendto, payload, (host, port))

        # 2. Syslog over TCP
        elif target_type == "syslog_tcp":
            if fmt == "json":
                payload = (json.dumps(log_item.get("parsed_json", {}), ensure_ascii=False) + "\n").encode("utf-8")
            else:
                payload = (log_item.get("raw", "") + "\n").encode("utf-8")

            # Open TCP connection with 3-second timeout
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=3.0
            )
            writer.write(payload)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        # 3. HTTP Webhook
        elif target_type == "http_webhook":
            client = get_http_client()
            webhook_payload = {
                "device": log_item.get("source_ip"),
                "vendor": log_item.get("vendor_type"),
                "timestamp": log_item.get("timestamp"),
                "severity": log_item.get("severity"),
                "facility": log_item.get("facility"),
                "tag": log_item.get("tag"),
                "mnemonic": log_item.get("mnemonic"),
                "data": log_item.get("parsed_json", {}),
                "raw": log_item.get("raw")
            }
            await client.post(
                host,
                json=webhook_payload,
                headers={"Content-Type": "application/json", "User-Agent": "SyslogForwarder/1.0"}
            )

        # Update in-memory counters
        _FORWARD_STATS[ep_id] = _FORWARD_STATS.get(ep_id, 0) + 1
        _LAST_FORWARD_TIME[ep_id] = datetime.now(get_app_timezone()).isoformat()

    except Exception as e:
        logger.warning("Failed forwarding to [%s] %s:%s (%s): %s", ep.get("name"), host, port, target_type, e)


async def evaluate_and_forward_logs(batch: List[Dict[str, Any]]):
    """
    Evaluates incoming batch of parsed logs and dispatches them to matching endpoints.
    Uses non-blocking background tasks.
    """
    endpoints = await get_all_forwarding_endpoints()
    active_eps = [ep for ep in endpoints if ep.get("enabled", 1)]
    if not active_eps or not batch:
        return

    for item in batch:
        for ep in active_eps:
            if matches_endpoint(item, ep):
                asyncio.create_task(dispatch_to_endpoint(ep, item))


# --- Test Dispatch ---

async def test_endpoint_dispatch(
    target_type: str,
    host: str,
    port: int = 514,
    forward_format: str = "raw"
) -> Dict[str, Any]:
    """Sends a sample test packet/payload to the specified target."""
    test_log = {
        "source_ip": "10.0.0.1",
        "vendor_type": "cisco",
        "timestamp": datetime.now(get_app_timezone()).isoformat(),
        "severity": 3,
        "facility": 23,
        "tag": "LINK",
        "mnemonic": "UPDOWN",
        "raw": "<189>%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down (Test Forwarding)",
        "parsed_json": {
            "vendor_type": "cisco",
            "cisco_facility": "LINK",
            "cisco_severity": 3,
            "mnemonic": "UPDOWN",
            "message": "Interface GigabitEthernet0/1, changed state to down (Test Forwarding)",
            "test": True
        }
    }

    mock_ep = {
        "id": 0,
        "name": "Test Probe",
        "target_type": target_type,
        "host": host,
        "port": port,
        "forward_format": forward_format,
        "enabled": 1
    }

    try:
        await dispatch_to_endpoint(mock_ep, test_log)
        return {
            "success": True,
            "message": f"Successfully sent test {target_type.upper()} packet to {host}:{port}"
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Dispatch error: {str(e)}"
        }

