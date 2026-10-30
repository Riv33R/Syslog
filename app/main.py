import sys
import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Optional, List, Dict, Any
from pathlib import Path

# Silence benign WinError 10054 on Windows when clients (e.g. browser reloads) disconnect abruptly
if sys.platform == "win32":
    try:
        from asyncio.proactor_events import _ProactorBasePipeTransport
        _orig_call_connection_lost = _ProactorBasePipeTransport._call_connection_lost

        def _silenced_call_connection_lost(self, exc):
            try:
                _orig_call_connection_lost(self, exc)
            except (ConnectionResetError, BrokenPipeError):
                pass
            except OSError as e:
                if getattr(e, "winerror", None) == 10054:
                    pass
                else:
                    raise

        _ProactorBasePipeTransport._call_connection_lost = _silenced_call_connection_lost
    except Exception:
        pass

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, HttpUrl

from app.config import (
    SYSLOG_HOST,
    SYSLOG_PORT,
    SYSLOG_PORTS,
    WEB_HOST,
    WEB_PORT,
    RETENTION_DAYS,
    CLEANUP_INTERVAL_HOURS,
    DEVICES_DIR,
    DATA_DIR,
    get_app_timezone,
)
from app.storage import (
    init_registry_db,
    get_all_devices,
    get_device_info,
    query_device_logs,
    query_all_devices_logs,
    cleanup_retention_worker,
    get_all_settings,
    get_setting,
    update_settings,
    export_full_backup,
    import_full_backup,
)
from app.collector import (
    SyslogUdpProtocol,
    handle_tcp_client,
    batch_processing_worker,
    register_ws,
    unregister_ws,
    update_ws_filter,
    register_sse,
    unregister_sse,
    STATS,
)
from app.webhooks import (
    get_all_webhooks,
    create_webhook,
    delete_webhook,
    toggle_webhook,
    send_webhook_payload,
    close_http_client,
)
from app.forwarder import (
    get_all_forwarding_endpoints,
    create_forwarding_endpoint,
    update_forwarding_endpoint,
    delete_forwarding_endpoint,
    toggle_forwarding_endpoint,
    test_endpoint_dispatch,
    flush_forwarding_stats,
)

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("syslog.main")

# Background task references
_background_tasks: List[asyncio.Task] = []
_udp_transports: List[Any] = []
_tcp_servers: List[Any] = []
_bound_ports: List[int] = []

# Jinja2 templates directory
TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


async def periodic_retention_task():
    """Periodically runs cleanup for logs older than RETENTION_DAYS."""
    while True:
        try:
            await asyncio.sleep(CLEANUP_INTERVAL_HOURS * 3600)
            await cleanup_retention_worker(RETENTION_DAYS)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("Error in retention cleanup task: %s", e)


async def periodic_stats_flush_task():
    """Periodically flushes in-memory forwarding counters to SQLite."""
    while True:
        try:
            await asyncio.sleep(10)
            await flush_forwarding_stats()
        except asyncio.CancelledError:
            await flush_forwarding_stats()
            break
        except Exception as e:
            logger.error("Error flushing forwarding stats: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _udp_transports, _tcp_servers, _bound_ports

    logger.info("Initializing Syslog Aggregator...")
    await init_registry_db()

    loop = asyncio.get_running_loop()

    # Filter out WinError 10054 callback noise on Windows
    if sys.platform == "win32":
        def win_exception_handler(l, context):
            exception = context.get("exception")
            if isinstance(exception, ConnectionResetError) and getattr(exception, "winerror", None) == 10054:
                return
            l.default_exception_handler(context)
        loop.set_exception_handler(win_exception_handler)

    # 1. Start batch processor worker
    batch_task = asyncio.create_task(batch_processing_worker())
    _background_tasks.append(batch_task)

    # 2. Start UDP and TCP syslog listeners on all configured ports (e.g. 514 and 1514)
    for port in SYSLOG_PORTS:
        # UDP
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda p=port: SyslogUdpProtocol(port=p),
                local_addr=(SYSLOG_HOST, port)
            )
            _udp_transports.append(transport)
            if port not in _bound_ports:
                _bound_ports.append(port)
            logger.info("UDP Syslog listener active on %s:%d", SYSLOG_HOST, port)
        except Exception as e:
            logger.warning("Could not bind UDP on %s:%d: %s", SYSLOG_HOST, port, e)

        # TCP
        try:
            server = await asyncio.start_server(
                handle_tcp_client,
                host=SYSLOG_HOST,
                port=port
            )
            _tcp_servers.append(server)
            if port not in _bound_ports:
                _bound_ports.append(port)
            logger.info("TCP Syslog server active on %s:%d", SYSLOG_HOST, port)
        except Exception as e:
            logger.warning("Could not bind TCP on %s:%d: %s", SYSLOG_HOST, port, e)

    # 3. Start background worker tasks
    retention_task = asyncio.create_task(periodic_retention_task())
    _background_tasks.append(retention_task)
    stats_flush_task = asyncio.create_task(periodic_stats_flush_task())
    _background_tasks.append(stats_flush_task)

    logger.info("Syslog Aggregator Engine is fully running on ports: %s", _bound_ports)

    yield

    logger.info("Shutting down Syslog Aggregator...")
    # Stop network listeners
    for t in _udp_transports:
        t.close()
    for s in _tcp_servers:
        s.close()
        await s.wait_closed()

    # Cancel background tasks
    for task in _background_tasks:
        task.cancel()
    await asyncio.gather(*_background_tasks, return_exceptions=True)

    # Close HTTP client
    await close_http_client()
    logger.info("Syslog Aggregator shut down successfully.")


app = FastAPI(
    title="Production Syslog Aggregator",
    description="High-performance Syslog Aggregator with isolated per-device SQLite databases and specialized parsers.",
    version="1.0.0",
    lifespan=lifespan
)


# --- Pydantic Models ---

class WebhookCreateRequest(BaseModel):
    name: str
    target_url: str
    vendor: Optional[str] = None
    max_severity: Optional[int] = None
    action: Optional[str] = None
    filter_regex: Optional[str] = None

class WebhookToggleRequest(BaseModel):
    enabled: bool

class WebhookTestRequest(BaseModel):
    target_url: str
    sample_payload: Optional[Dict[str, Any]] = None

class ForwardingEndpointCreateRequest(BaseModel):
    name: str
    target_type: str  # 'syslog_udp', 'syslog_tcp', 'http_webhook'
    host: str
    port: int = 514
    filter_source_ip: Optional[str] = None
    filter_vendor: Optional[str] = None
    filter_max_severity: Optional[int] = None
    forward_format: str = "raw"
    enabled: bool = True

class ForwardingEndpointToggleRequest(BaseModel):
    enabled: bool

class ForwardingEndpointTestRequest(BaseModel):
    target_type: str
    host: str
    port: int = 514
    forward_format: str = "raw"


# --- Web UI Route ---

@app.get("/", response_class=HTMLResponse)
async def serve_index(request: Request):
    """Renders the main modern dark theme Single File Component dashboard."""
    settings = await get_all_settings()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "retention_days": settings.get("retention_days", str(RETENTION_DAYS)),
            "timezone": settings.get("timezone", "Europe/Chisinau"),
            "settings": settings,
        }
    )


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """Silence browser favicon requests."""
    return Response(status_code=204)


# --- REST API Endpoints ---

@app.get("/api/v1/devices")
async def list_devices():
    """Returns list of registered devices, their vendor, log counts, and online status."""
    devices = await get_all_devices()
    return {"devices": devices, "total": len(devices)}


@app.get("/api/v1/devices/{ip}")
async def get_device(ip: str):
    """Retrieves metadata for a specific device."""
    dev = await get_device_info(ip)
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    return dev


@app.get("/api/v1/devices/{ip}/logs")
async def get_device_logs(
    ip: str,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    severity: Optional[int] = Query(default=None, ge=0, le=7),
    severity_max: Optional[int] = Query(default=None, ge=0, le=7),
    facility: Optional[int] = Query(default=None, ge=0, le=23),
    vendor_type: Optional[str] = Query(default=None),
    q: Optional[str] = Query(default=None),
    start_time: Optional[str] = Query(default=None),
    end_time: Optional[str] = Query(default=None),
    tag: Optional[str] = Query(default=None),
):
    """
    Queries archival logs from the chosen device's isolated SQLite database.
    Supports filtering by severity (exact or max threshold), facility, vendor_type,
    time range, tag/mnemonic, and full-text keyword search.
    """
    logs, total = await query_device_logs(
        ip=ip,
        limit=limit,
        offset=offset,
        severity=severity,
        severity_max=severity_max,
        facility=facility,
        vendor_type=vendor_type,
        q=q,
        start_time=start_time,
        end_time=end_time,
        tag=tag,
    )
    return {
        "device": ip,
        "total": total,
        "limit": limit,
        "offset": offset,
        "logs": logs
    }


@app.get("/api/v1/logs")
async def get_all_logs(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    severity: Optional[int] = Query(default=None, ge=0, le=7),
    severity_max: Optional[int] = Query(default=None, ge=0, le=7),
    facility: Optional[int] = Query(default=None, ge=0, le=23),
    vendor_type: Optional[str] = Query(default=None),
    q: Optional[str] = Query(default=None),
    start_time: Optional[str] = Query(default=None),
    end_time: Optional[str] = Query(default=None),
    tag: Optional[str] = Query(default=None),
):
    """
    Queries archival logs across all device databases with unified filtering and pagination.
    """
    logs, total = await query_all_devices_logs(
        limit=limit,
        offset=offset,
        severity=severity,
        severity_max=severity_max,
        facility=facility,
        vendor_type=vendor_type,
        q=q,
        start_time=start_time,
        end_time=end_time,
        tag=tag,
    )
    return {
        "device": "all",
        "total": total,
        "limit": limit,
        "offset": offset,
        "logs": logs
    }


@app.get("/api/v1/devices/{ip}/stream")
async def stream_device_logs(ip: str):
    """
    Server-Sent Events (SSE) stream for external bots or microservices
    subscribing to real-time events from a specific device.
    """
    async def event_generator():
        queue = register_sse(target_ip=ip)
        try:
            # Yield initial keepalive
            yield f": connected to device stream {ip}\n\n"
            while True:
                log_item = await queue.get()
                import json
                data = json.dumps(log_item, ensure_ascii=False)
                yield f"data: {data}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            unregister_sse(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@app.get("/api/v1/stats")
async def get_system_stats():
    """Returns engine runtime metrics and statistics."""
    devices = await get_all_devices()
    total_logs_stored = sum(d.get("log_count", 0) for d in devices)
    online_count = sum(1 for d in devices if d.get("is_online", False))
    settings = await get_all_settings()
    tz_name = settings.get("timezone", "Europe/Chisinau")
    from datetime import datetime
    now_in_tz = datetime.now(get_app_timezone(tz_name)).isoformat()

    return {
        "stats": STATS,
        "listening_ports": _bound_ports,
        "devices_count": len(devices),
        "devices_online": online_count,
        "total_logs_stored": total_logs_stored,
        "retention_days": int(settings.get("retention_days", RETENTION_DAYS)),
        "timezone": tz_name,
        "server_time": now_in_tz,
        "storage_dir": str(DATA_DIR),
        "settings": settings,
    }


# --- Webhooks REST API ---

@app.get("/api/v1/webhooks")
async def list_webhooks():
    rules = await get_all_webhooks()
    return {"webhooks": rules}


@app.post("/api/v1/webhooks")
async def add_webhook(req: WebhookCreateRequest):
    rule_id = await create_webhook(
        name=req.name,
        target_url=req.target_url,
        vendor=req.vendor,
        max_severity=req.max_severity,
        action=req.action,
        filter_regex=req.filter_regex
    )
    return {"status": "created", "id": rule_id}


@app.delete("/api/v1/webhooks/{webhook_id}")
async def remove_webhook(webhook_id: int):
    success = await delete_webhook(webhook_id)
    if not success:
        raise HTTPException(status_code=404, detail="Webhook rule not found")
    return {"status": "deleted", "id": webhook_id}


@app.post("/api/v1/webhooks/{webhook_id}/toggle")
async def toggle_webhook_rule(webhook_id: int, req: WebhookToggleRequest):
    success = await toggle_webhook(webhook_id, req.enabled)
    if not success:
        raise HTTPException(status_code=404, detail="Webhook rule not found")
    return {"status": "updated", "id": webhook_id, "enabled": req.enabled}


@app.post("/api/v1/webhooks/test")
async def test_webhook_endpoint(req: WebhookTestRequest):
    """Sends a sample test payload to a target URL."""
    payload = req.sample_payload or {
        "device": "192.168.1.1",
        "vendor": "cisco",
        "timestamp": "2026-10-29T11:00:00Z",
        "severity": 3,
        "facility": 16,
        "tag": "LINK",
        "mnemonic": "UPDOWN",
        "data": {
            "vendor_type": "cisco",
            "cisco_facility": "LINK",
            "cisco_severity": 3,
            "mnemonic": "UPDOWN",
            "message": "Interface GigabitEthernet0/1, changed state to down"
        },
        "raw": "%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down"
    }
    try:
        await send_webhook_payload(req.target_url, payload, "Manual Test")
        return {"status": "success", "message": f"Test payload dispatched to {req.target_url}"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/retention/cleanup")
async def trigger_retention_cleanup():
    """Manually triggers retention cleanup."""
    asyncio.create_task(cleanup_retention_worker(RETENTION_DAYS))
    return {"status": "cleanup_started", "retention_days": RETENTION_DAYS}


# --- Forwarding Endpoints & Destinations REST API ---

@app.get("/api/v1/forwarding/endpoints")
async def list_forwarding_endpoints():
    """Returns list of configured forwarding destinations and live packet stats."""
    endpoints = await get_all_forwarding_endpoints()
    return {"endpoints": endpoints}


@app.post("/api/v1/forwarding/endpoints")
async def add_forwarding_endpoint(req: ForwardingEndpointCreateRequest):
    """Creates a new destination target to forward logs to."""
    ep_id = await create_forwarding_endpoint(
        name=req.name,
        target_type=req.target_type,
        host=req.host,
        port=req.port,
        filter_source_ip=req.filter_source_ip,
        filter_vendor=req.filter_vendor,
        filter_max_severity=req.filter_max_severity,
        forward_format=req.forward_format,
        enabled=req.enabled
    )
    return {"status": "created", "id": ep_id}


@app.put("/api/v1/forwarding/endpoints/{endpoint_id}")
async def edit_forwarding_endpoint(endpoint_id: int, req: ForwardingEndpointCreateRequest):
    """Updates an existing destination target."""
    success = await update_forwarding_endpoint(
        endpoint_id=endpoint_id,
        name=req.name,
        target_type=req.target_type,
        host=req.host,
        port=req.port,
        filter_source_ip=req.filter_source_ip,
        filter_vendor=req.filter_vendor,
        filter_max_severity=req.filter_max_severity,
        forward_format=req.forward_format,
        enabled=req.enabled
    )
    if not success:
        raise HTTPException(status_code=404, detail="Forwarding endpoint not found")
    return {"status": "updated", "id": endpoint_id}


@app.delete("/api/v1/forwarding/endpoints/{endpoint_id}")
async def remove_forwarding_endpoint(endpoint_id: int):
    """Deletes a forwarding destination."""
    success = await delete_forwarding_endpoint(endpoint_id)
    if not success:
        raise HTTPException(status_code=404, detail="Forwarding endpoint not found")
    return {"status": "deleted", "id": endpoint_id}


@app.post("/api/v1/forwarding/endpoints/{endpoint_id}/toggle")
async def toggle_forwarding(endpoint_id: int, req: ForwardingEndpointToggleRequest):
    """Toggles active/paused state for a forwarding target."""
    success = await toggle_forwarding_endpoint(endpoint_id, req.enabled)
    if not success:
        raise HTTPException(status_code=404, detail="Forwarding endpoint not found")
    return {"status": "updated", "id": endpoint_id, "enabled": req.enabled}


@app.post("/api/v1/forwarding/test")
async def test_forwarding(req: ForwardingEndpointTestRequest):
    """Sends a sample probe packet to test destination reachability."""
    res = await test_endpoint_dispatch(
        target_type=req.target_type,
        host=req.host,
        port=req.port,
        forward_format=req.forward_format
    )
    return res


# --- System Settings, Timezone & Disaster Recovery Backup ---

class SettingsUpdateRequest(BaseModel):
    timezone: Optional[str] = None
    language: Optional[str] = None
    retention_days: Optional[int] = None
    date_format: Optional[str] = None
    autoscroll: Optional[bool] = None


@app.get("/api/v1/settings")
async def get_settings():
    """Returns persistent system settings."""
    settings = await get_all_settings()
    return {"settings": settings}


@app.post("/api/v1/settings")
async def save_settings(req: SettingsUpdateRequest):
    """Updates persistent system settings."""
    updates = {}
    if req.timezone is not None:
        updates["timezone"] = req.timezone
    if req.language is not None:
        updates["language"] = req.language
    if req.retention_days is not None:
        updates["retention_days"] = str(req.retention_days)
    if req.date_format is not None:
        updates["date_format"] = req.date_format
    if req.autoscroll is not None:
        updates["autoscroll"] = str(req.autoscroll).lower()

    updated = await update_settings(updates)
    return {"status": "ok", "settings": updated}


@app.get("/api/v1/backup")
async def export_backup():
    """Exports entire aggregator configuration (settings, forwarding targets, webhooks, devices) for disaster recovery."""
    backup_data = await export_full_backup()
    return backup_data


@app.post("/api/v1/restore")
async def import_backup(data: Dict[str, Any]):
    """Restores aggregator configuration from a JSON backup."""
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Invalid backup payload format")
    results = await import_full_backup(data)
    return {"status": "restored", "summary": results}


# --- WebSocket Live Stream ---

@app.websocket("/ws/logs")
async def websocket_logs_endpoint(websocket: WebSocket):
    """
    Bidirectional WebSocket endpoint for the web dashboard.
    Receives real-time logs matching current device filter.
    Accepts commands:
      - {"action": "filter", "ip": "192.168.1.1"}
      - {"action": "filter", "ip": null}
      - {"action": "ping"}
    """
    await websocket.accept()
    register_ws(websocket, target_ip=None)

    try:
        while True:
            msg = await websocket.receive_json()
            action = msg.get("action")
            if action == "filter":
                target_ip = msg.get("ip")
                update_ws_filter(websocket, target_ip)
                await websocket.send_json({"type": "info", "message": f"Filter updated to {target_ip or 'ALL'}"})
            elif action == "ping":
                await websocket.send_json({"type": "pong"})
    except (WebSocketDisconnect, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        logger.debug("WebSocket client closed: %s", e)
    finally:
        unregister_ws(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=WEB_HOST, port=WEB_PORT, reload=False)
