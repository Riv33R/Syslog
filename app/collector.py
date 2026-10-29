import asyncio
import logging
from typing import Set, Dict, Any, Optional, List, Tuple
from asyncio import DatagramProtocol, StreamReader, StreamWriter

from app.config import (
    SYSLOG_HOST,
    SYSLOG_PORT,
    BATCH_SIZE,
    BATCH_TIMEOUT_SEC,
    MAX_QUEUE_SIZE,
)
from app.parsers import parse_syslog_message
from app.storage import insert_logs_batch
from app.webhooks import evaluate_and_dispatch_webhooks
from app.forwarder import evaluate_and_forward_logs

logger = logging.getLogger("syslog.collector")

# In-memory ingestion queue to decouple network reception from disk I/O
_INGEST_QUEUE: asyncio.Queue = asyncio.Queue(maxsize=MAX_QUEUE_SIZE)

# Active live stream subscribers
# WebSocket clients: map ws -> optional target_ip filter
_WS_CLIENTS: Dict[Any, Optional[str]] = {}
# SSE client queues: map queue -> optional target_ip filter
_SSE_CLIENTS: Dict[asyncio.Queue, Optional[str]] = {}

# Statistics
STATS = {
    "total_received": 0,
    "total_dropped": 0,
    "udp_received": 0,
    "tcp_received": 0,
}

# --- Subscription Hub ---

def register_ws(ws: Any, target_ip: Optional[str] = None):
    _WS_CLIENTS[ws] = target_ip

def unregister_ws(ws: Any):
    _WS_CLIENTS.pop(ws, None)

def update_ws_filter(ws: Any, target_ip: Optional[str] = None):
    if ws in _WS_CLIENTS:
        _WS_CLIENTS[ws] = target_ip

def register_sse(target_ip: Optional[str] = None) -> asyncio.Queue:
    q = asyncio.Queue(maxsize=500)
    _SSE_CLIENTS[q] = target_ip
    return q

def unregister_sse(q: asyncio.Queue):
    _SSE_CLIENTS.pop(q, None)

async def broadcast_to_subscribers(log_item: Dict[str, Any]):
    """Broadcasts a newly processed log to active WebSockets and SSE queues."""
    source_ip = log_item.get("source_ip")

    # Broadcast to WebSockets
    dead_ws = []
    for ws, filter_ip in list(_WS_CLIENTS.items()):
        if filter_ip is None or filter_ip == source_ip:
            try:
                await ws.send_json(log_item)
            except Exception:
                dead_ws.append(ws)
    for ws in dead_ws:
        unregister_ws(ws)

    # Broadcast to SSE Queues
    dead_sse = []
    for q, filter_ip in list(_SSE_CLIENTS.items()):
        if filter_ip is None or filter_ip == source_ip:
            try:
                q.put_nowait(log_item)
            except asyncio.QueueFull:
                pass
            except Exception:
                dead_sse.append(q)
    for q in dead_sse:
        unregister_sse(q)


# --- UDP Protocol Handler ---

class SyslogUdpProtocol(DatagramProtocol):
    def __init__(self, port: int = 514):
        self.port = port
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        logger.info("Syslog UDP listener ready on %s:%d", SYSLOG_HOST, self.port)

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        STATS["total_received"] += 1
        STATS["udp_received"] += 1
        raw_text = data.decode("utf-8", errors="replace").strip()
        if not raw_text:
            return

        ip = addr[0]
        try:
            _INGEST_QUEUE.put_nowait((raw_text, ip))
        except asyncio.QueueFull:
            STATS["total_dropped"] += 1
            if STATS["total_dropped"] % 500 == 1:
                logger.warning("Ingest queue full! Dropped %d packets.", STATS["total_dropped"])

    def error_received(self, exc):
        logger.error("Syslog UDP error: %s", exc)


# --- TCP Stream Handler ---

async def handle_tcp_client(reader: StreamReader, writer: StreamWriter):
    peer = writer.get_extra_info("peername")
    client_ip = peer[0] if peer else "unknown"
    logger.debug("TCP Syslog client connected from %s", client_ip)

    buffer = ""
    try:
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                break

            text = chunk.decode("utf-8", errors="replace")
            buffer += text

            # Process newline-delimited syslog messages
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.strip("\r").strip()
                if not line:
                    continue

                STATS["total_received"] += 1
                STATS["tcp_received"] += 1
                try:
                    _INGEST_QUEUE.put_nowait((line, client_ip))
                except asyncio.QueueFull:
                    STATS["total_dropped"] += 1
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.debug("TCP client %s error: %s", client_ip, e)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# --- Background Batch Processing Worker ---

async def batch_processing_worker():
    """
    Consumes from _INGEST_QUEUE, parses messages via the specialized pipeline,
    persists in isolated device databases, broadcasts to live views, and triggers webhooks.
    """
    logger.info("Syslog batch processing worker started.")
    while True:
        try:
            batch_raw: List[Tuple[str, str]] = []

            # Wait for at least one item
            first_item = await _INGEST_QUEUE.get()
            batch_raw.append(first_item)
            _INGEST_QUEUE.task_done()

            # Drain up to BATCH_SIZE items within BATCH_TIMEOUT_SEC
            deadline = asyncio.get_running_loop().time() + BATCH_TIMEOUT_SEC
            while len(batch_raw) < BATCH_SIZE:
                remaining_time = deadline - asyncio.get_running_loop().time()
                if remaining_time <= 0:
                    break
                try:
                    item = await asyncio.wait_for(_INGEST_QUEUE.get(), timeout=remaining_time)
                    batch_raw.append(item)
                    _INGEST_QUEUE.task_done()
                except asyncio.TimeoutError:
                    break

            # Parse all messages in batch
            parsed_batch: List[Dict[str, Any]] = []
            for raw_text, ip in batch_raw:
                try:
                    parsed = parse_syslog_message(raw_text, ip)
                    parsed_batch.append(parsed)
                except Exception as e:
                    logger.error("Parsing failed for message from %s: %s", ip, e, exc_info=True)

            if parsed_batch:
                # 1. Batch insert into isolated per-device databases & update registry
                await insert_logs_batch(parsed_batch)

                # 2. Broadcast to live WebSockets & SSE subscribers
                for item in parsed_batch:
                    await broadcast_to_subscribers(item)

                # 3. Fire-and-forget webhook rules evaluation
                await evaluate_and_dispatch_webhooks(parsed_batch)

                # 4. Multi-target forwarding (Syslog UDP, Syslog TCP, Webhooks)
                await evaluate_and_forward_logs(parsed_batch)

        except asyncio.CancelledError:
            logger.info("Batch processing worker cancelled.")
            break
        except Exception as e:
            logger.error("Error in batch processing worker: %s", e, exc_info=True)
            await asyncio.sleep(0.5)
