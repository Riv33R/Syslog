import re
import socket
import logging
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
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

# Fast PRI Regex for microsecond severity extraction (<PRI>)
_FAST_PRI_REGEX = re.compile(r"^<(\d{1,3})>")

# Cached active endpoints in RAM for zero-latency lookup (Pre-Parse pipeline)
_CACHED_ENDPOINTS: List[Dict[str, Any]] = []
_CACHE_INITIALIZED: bool = False

# Hostname-to-IP cache to eliminate blocking DNS queries in the fast lane
_DNS_CACHE: Dict[str, str] = {}


# --- Persistent TCP Connection Manager ---

class PersistentTcpSender:
    """
    Maintains a persistent, keep-alive TCP connection to a remote Syslog target.
    Eliminates socket exhaustion (TIME_WAIT / WSAEADDRINUSE) by reusing the socket.
    Automatically reconnects on connection loss.
    """
    def __init__(self, host: str, port: int, connect_timeout: float = 3.0):
        self.host = host
        self.port = port
        self.connect_timeout = connect_timeout
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self._lock = asyncio.Lock()

    async def _ensure_connected(self) -> bool:
        if self.writer is not None and not self.writer.is_closing():
            return True
        self._cleanup()
        try:
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.connect_timeout
            )
            logger.info("Persistent TCP forwarder connected to %s:%d", self.host, self.port)
            return True
        except Exception as e:
            logger.warning("Failed to connect persistent TCP to %s:%d: %s", self.host, self.port, e)
            self._cleanup()
            return False

    def _cleanup(self):
        if self.writer:
            try:
                self.writer.close()
            except Exception:
                pass
        self.writer = None
        self.reader = None

    async def send(self, payload: bytes) -> bool:
        async with self._lock:
            for attempt in range(2):
                if not await self._ensure_connected():
                    return False
                try:
                    self.writer.write(payload)
                    await self.writer.drain()
                    return True
                except Exception as e:
                    logger.debug("TCP send error on %s:%d (attempt %d): %s - reconnecting", self.host, self.port, attempt + 1, e)
                    self._cleanup()
            return False

    async def close(self):
        async with self._lock:
            if self.writer:
                try:
                    self.writer.close()
                    await self.writer.wait_closed()
                except Exception:
                    pass
            self.writer = None
            self.reader = None


# Persistent TCP Senders Pool: map (host, port) -> PersistentTcpSender
_TCP_POOL: Dict[Tuple[str, int], PersistentTcpSender] = {}


def get_tcp_sender(host: str, port: int) -> PersistentTcpSender:
    key = (host, port)
    if key not in _TCP_POOL:
        _TCP_POOL[key] = PersistentTcpSender(host, port)
    return _TCP_POOL[key]


async def close_persistent_forwarders():
    """Closes all active persistent TCP connections on application shutdown."""
    for sender in list(_TCP_POOL.values()):
        await sender.close()
    _TCP_POOL.clear()
    logger.info("All persistent TCP forwarders closed cleanly.")


# --- In-Memory Caching & Database Operations ---

def resolve_cached_host(host: str) -> str:
    """Fast resolve IP or cached domain to avoid blocking gethostbyname."""
    if host in _DNS_CACHE:
        return _DNS_CACHE[host]
    try:
        ip = socket.gethostbyname(host)
        _DNS_CACHE[host] = ip
        return ip
    except Exception:
        return host


async def refresh_endpoints_cache() -> List[Dict[str, Any]]:
    """Loads all forwarding endpoints from registry DB into fast memory cache."""
    global _CACHED_ENDPOINTS, _CACHE_INITIALIZED
    endpoints = await get_all_forwarding_endpoints()
    _CACHED_ENDPOINTS = endpoints
    _CACHE_INITIALIZED = True

    # Pre-resolve hostnames for active endpoints
    for ep in _CACHED_ENDPOINTS:
        if ep.get("enabled", 1):
            resolve_cached_host(ep.get("host", ""))

    logger.debug("Refreshed forwarding cache: %d endpoints loaded", len(_CACHED_ENDPOINTS))
    return _CACHED_ENDPOINTS


def get_cached_active_endpoints() -> List[Dict[str, Any]]:
    """Returns enabled endpoints from memory cache (0ms latency)."""
    return [ep for ep in _CACHED_ENDPOINTS if ep.get("enabled", 1)]


async def get_all_forwarding_endpoints() -> List[Dict[str, Any]]:
    endpoints = []
    try:
        async with aiosqlite.connect(REGISTRY_DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM forwarding_endpoints ORDER BY id ASC") as cursor:
                async for row in cursor:
                    ep = dict(row)
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
        new_id = cursor.lastrowid
        logger.info("Created forwarding endpoint [%s] -> %s:%d (%s)", name, host, port, target_type)

    await refresh_endpoints_cache()
    return new_id


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
        success = cursor.rowcount > 0

    await refresh_endpoints_cache()
    return success


async def delete_forwarding_endpoint(endpoint_id: int) -> bool:
    async with aiosqlite.connect(REGISTRY_DB_PATH) as db:
        cursor = await db.execute("DELETE FROM forwarding_endpoints WHERE id = ?", (endpoint_id,))
        await db.commit()
        _FORWARD_STATS.pop(endpoint_id, None)
        _LAST_FORWARD_TIME.pop(endpoint_id, None)
        success = cursor.rowcount > 0

    await refresh_endpoints_cache()
    return success


async def toggle_forwarding_endpoint(endpoint_id: int, enabled: bool) -> bool:
    async with aiosqlite.connect(REGISTRY_DB_PATH) as db:
        cursor = await db.execute(
            "UPDATE forwarding_endpoints SET enabled = ? WHERE id = ?",
            (1 if enabled else 0, endpoint_id)
        )
        await db.commit()
        success = cursor.rowcount > 0

    await refresh_endpoints_cache()
    return success


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


# --- Microsecond PRI & Severity Extraction ---

def extract_pri_severity(raw_text: str) -> int:
    """
    Extracts severity (0-7) from RFC 3164/5424 <PRI> header in ~50 nanoseconds.
    Formula: severity = PRI & 7.
    Default: 6 (Informational).
    """
    m = _FAST_PRI_REGEX.match(raw_text.lstrip())
    if m:
        try:
            return int(m.group(1)) & 7
        except ValueError:
            pass
    return 6


# --- Pre-Parse Matching & Fast Dispatch ---

def matches_raw_endpoint(source_ip: str, raw_text: str, ep: Dict[str, Any]) -> bool:
    """
    Checks if raw incoming syslog message satisfies endpoint criteria BEFORE parsing.
    Filters available pre-parsing:
      - enabled
      - filter_source_ip
      - filter_max_severity (via fast PRI extraction)
    Endpoints that require vendor filtering are skipped here and handled post-parsing.
    """
    if not ep.get("enabled", 1):
        return False

    # Vendor filter cannot be matched pre-parse unless it is empty or 'all'
    filter_vendor = ep.get("filter_vendor")
    if filter_vendor and filter_vendor.strip() and filter_vendor.lower() != "all":
        return False

    # Endpoints requesting normalized JSON format require parsing and run post-parsing
    if ep.get("forward_format") == "json":
        return False

    # 1. Source IP Filter
    filter_ip = ep.get("filter_source_ip")
    if filter_ip and filter_ip.strip():
        if source_ip != filter_ip.strip():
            return False

    # 2. Severity Filter
    max_sev = ep.get("filter_max_severity")
    if max_sev is not None and max_sev != "":
        sev = extract_pri_severity(raw_text)
        if sev > int(max_sev):
            return False

    return True


def dispatch_pre_parse_forwarding(raw_text: str, source_ip: str, raw_bytes: Optional[bytes] = None):
    """
    HIGH-PERFORMANCE PRE-PARSE FAST LANE.
    Transmits exactly what was received ('передаем то что получили') directly to
    remote destinations before parsing, database writes, or WebSockets.
    - Syslog UDP: Direct non-blocking socket send in microseconds without thread hops.
    - Syslog TCP: Sent through keep-alive persistent TCP connection pool.
    - Webhook: Scheduled asynchronously without blocking caller.
    """
    active_eps = get_cached_active_endpoints()
    if not active_eps or not raw_text:
        return

    now_iso = datetime.now(get_app_timezone()).isoformat()

    for ep in active_eps:
        if matches_raw_endpoint(source_ip, raw_text, ep):
            ep_id = ep["id"]
            target_type = ep.get("target_type", "syslog_udp")
            host = resolve_cached_host(ep.get("host", ""))
            port = int(ep.get("port", 514))

            # --- 1. Syslog over UDP (Sub-microsecond direct send) ---
            if target_type == "syslog_udp":
                try:
                    payload = raw_bytes if raw_bytes is not None else raw_text.encode("utf-8")
                    _UDP_SOCK.sendto(payload, (host, port))
                    _FORWARD_STATS[ep_id] = _FORWARD_STATS.get(ep_id, 0) + 1
                    _LAST_FORWARD_TIME[ep_id] = now_iso
                except BlockingIOError:
                    pass
                except OSError as e:
                    # Filter benign transient ICMP errors on Windows
                    if getattr(e, "winerror", None) != 10054:
                        logger.warning("UDP fast-forward error to [%s] %s:%d: %s", ep.get("name"), host, port, e)

            # --- 2. Syslog over TCP (Persistent keep-alive connection) ---
            elif target_type == "syslog_tcp":
                asyncio.create_task(_send_tcp_fast(ep_id, host, port, raw_text, now_iso))

            # --- 3. HTTP Webhook ---
            elif target_type == "http_webhook":
                asyncio.create_task(_send_webhook_fast(ep_id, host, source_ip, raw_text, now_iso))


async def _send_tcp_fast(ep_id: int, host: str, port: int, raw_text: str, now_iso: str):
    """Asynchronously forwards raw line via persistent TCP sender."""
    try:
        sender = get_tcp_sender(host, port)
        payload = (raw_text.rstrip("\r\n") + "\n").encode("utf-8")
        success = await sender.send(payload)
        if success:
            _FORWARD_STATS[ep_id] = _FORWARD_STATS.get(ep_id, 0) + 1
            _LAST_FORWARD_TIME[ep_id] = now_iso
    except Exception as e:
        logger.debug("TCP forward failed for ep %d: %s", ep_id, e)


async def _send_webhook_fast(ep_id: int, url: str, source_ip: str, raw_text: str, now_iso: str):
    """Asynchronously forwards raw log event via HTTP POST."""
    try:
        client = get_http_client()
        sev = extract_pri_severity(raw_text)
        payload = {
            "device": source_ip,
            "timestamp": now_iso,
            "severity": sev,
            "raw": raw_text
        }
        resp = await client.post(
            url,
            json=payload,
            headers={"Content-Type": "application/json", "User-Agent": "SyslogForwarder/1.0"}
        )
        if resp.status_code < 400:
            _FORWARD_STATS[ep_id] = _FORWARD_STATS.get(ep_id, 0) + 1
            _LAST_FORWARD_TIME[ep_id] = now_iso
    except Exception as e:
        logger.debug("Webhook forward failed for ep %d: %s", ep_id, e)


# --- Post-Parse Vendor-Filtered Forwarding (Fallback Lane) ---

def matches_endpoint(log_item: Dict[str, Any], ep: Dict[str, Any]) -> bool:
    """
    Standard matching logic on parsed log item (used for vendor-filtered endpoints and tests).
    """
    if not ep.get("enabled", 1):
        return False

    # 1. Source IP
    filter_ip = ep.get("filter_source_ip")
    if filter_ip and filter_ip.strip():
        if log_item.get("source_ip") != filter_ip.strip():
            return False

    # 2. Vendor
    filter_vendor = ep.get("filter_vendor")
    if filter_vendor and filter_vendor.strip() and filter_vendor.lower() != "all":
        if log_item.get("vendor_type", "").lower() != filter_vendor.strip().lower():
            return False

    # 3. Severity
    max_sev = ep.get("filter_max_severity")
    if max_sev is not None and max_sev != "":
        if log_item.get("severity", 999) > int(max_sev):
            return False

    return True


async def forward_vendor_filtered_logs(batch: List[Dict[str, Any]]):
    """
    Post-parse lane: only evaluated for endpoints that specifically require vendor matching
    (e.g., 'Cisco only', 'FortiGate only').
    """
    active_eps = get_cached_active_endpoints()
    vendor_eps = [
        ep for ep in active_eps
        if ep.get("filter_vendor") and ep.get("filter_vendor").strip().lower() != "all"
    ]
    if not vendor_eps or not batch:
        return

    now_iso = datetime.now(get_app_timezone()).isoformat()

    for item in batch:
        for ep in vendor_eps:
            if matches_endpoint(item, ep):
                ep_id = ep["id"]
                target_type = ep.get("target_type", "syslog_udp")
                host = resolve_cached_host(ep.get("host", ""))
                port = int(ep.get("port", 514))
                raw_text = item.get("raw", "")

                if target_type == "syslog_udp":
                    try:
                        _UDP_SOCK.sendto(raw_text.encode("utf-8"), (host, port))
                        _FORWARD_STATS[ep_id] = _FORWARD_STATS.get(ep_id, 0) + 1
                        _LAST_FORWARD_TIME[ep_id] = now_iso
                    except Exception:
                        pass
                elif target_type == "syslog_tcp":
                    asyncio.create_task(_send_tcp_fast(ep_id, host, port, raw_text, now_iso))
                elif target_type == "http_webhook":
                    asyncio.create_task(_send_webhook_fast(ep_id, host, item.get("source_ip", ""), raw_text, now_iso))


# Backward compatibility wrapper
async def evaluate_and_forward_logs(batch: List[Dict[str, Any]]):
    """Backward compatibility wrapper delegating to post-parse vendor forwarder."""
    await forward_vendor_filtered_logs(batch)


# --- Test Dispatch Probe ---

async def test_endpoint_dispatch(
    target_type: str,
    host: str,
    port: int = 514,
    forward_format: str = "raw"
) -> Dict[str, Any]:
    """Sends a sample test packet/payload to the specified target."""
    test_raw = "<189>%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down (Test Probe)"
    target_host = resolve_cached_host(host)

    try:
        if target_type == "syslog_udp":
            _UDP_SOCK.sendto(test_raw.encode("utf-8"), (target_host, int(port)))
            return {"success": True, "message": f"Successfully sent UDP Syslog probe to {host}:{port}"}

        elif target_type == "syslog_tcp":
            sender = get_tcp_sender(target_host, int(port))
            ok = await sender.send((test_raw + "\n").encode("utf-8"))
            if ok:
                return {"success": True, "message": f"Successfully sent TCP Syslog probe to {host}:{port}"}
            else:
                return {"success": False, "message": f"Could not connect or send to TCP {host}:{port}"}

        elif target_type == "http_webhook":
            client = get_http_client()
            resp = await client.post(
                host,
                json={"device": "127.0.0.1", "severity": 3, "raw": test_raw, "test": True},
                headers={"Content-Type": "application/json", "User-Agent": "SyslogForwarder/1.0"}
            )
            return {
                "success": resp.status_code < 400,
                "message": f"Webhook returned HTTP status {resp.status_code}"
            }
        else:
            return {"success": False, "message": f"Unknown target type: {target_type}"}

    except Exception as e:
        return {"success": False, "message": f"Dispatch error: {str(e)}"}
