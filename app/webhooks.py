import re
import logging
import asyncio
from typing import List, Dict, Any, Optional
import httpx
import aiosqlite
from datetime import datetime

from app.config import REGISTRY_DB_PATH, get_app_timezone

logger = logging.getLogger("syslog.webhooks")

# Shared HTTP client for high performance connection pooling
_HTTP_CLIENT: Optional[httpx.AsyncClient] = None

def get_http_client() -> httpx.AsyncClient:
    global _HTTP_CLIENT
    if _HTTP_CLIENT is None or _HTTP_CLIENT.is_closed:
        _HTTP_CLIENT = httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=3.0))
    return _HTTP_CLIENT

async def close_http_client():
    global _HTTP_CLIENT
    if _HTTP_CLIENT and not _HTTP_CLIENT.is_closed:
        await _HTTP_CLIENT.aclose()
        _HTTP_CLIENT = None

# Database operations for webhook rules
async def get_all_webhooks() -> List[Dict[str, Any]]:
    rules = []
    try:
        async with aiosqlite.connect(REGISTRY_DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM webhooks ORDER BY id ASC") as cursor:
                async for row in cursor:
                    rules.append(dict(row))
    except Exception as e:
        logger.error("Error loading webhooks: %s", e)
    return rules

async def create_webhook(
    name: str,
    target_url: str,
    vendor: Optional[str] = None,
    max_severity: Optional[int] = None,
    action: Optional[str] = None,
    filter_regex: Optional[str] = None
) -> int:
    now_iso = datetime.now(get_app_timezone()).isoformat()
    async with aiosqlite.connect(REGISTRY_DB_PATH) as db:
        cursor = await db.execute(
            """
            INSERT INTO webhooks (name, target_url, vendor, max_severity, action, filter_regex, enabled, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?)
            """,
            (name, target_url, vendor.lower() if vendor else None, max_severity, action.lower() if action else None, filter_regex, now_iso)
        )
        await db.commit()
        return cursor.lastrowid

async def delete_webhook(webhook_id: int) -> bool:
    async with aiosqlite.connect(REGISTRY_DB_PATH) as db:
        cursor = await db.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,))
        await db.commit()
        return cursor.rowcount > 0

async def toggle_webhook(webhook_id: int, enabled: bool) -> bool:
    async with aiosqlite.connect(REGISTRY_DB_PATH) as db:
        cursor = await db.execute("UPDATE webhooks SET enabled = ? WHERE id = ?", (1 if enabled else 0, webhook_id))
        await db.commit()
        return cursor.rowcount > 0

# Rule evaluation & dispatching
def matches_rule(log_item: Dict[str, Any], rule: Dict[str, Any]) -> bool:
    """Checks whether a parsed syslog entry satisfies a webhook rule."""
    if not rule.get("enabled", 1):
        return False

    # Vendor check
    rule_vendor = rule.get("vendor")
    if rule_vendor and rule_vendor != "" and rule_vendor.lower() != "all":
        if log_item.get("vendor_type", "").lower() != rule_vendor.lower():
            return False

    # Severity check (Syslog: 0 is highest emergency, <= max_severity means as severe or more)
    rule_sev = rule.get("max_severity")
    if rule_sev is not None:
        if log_item.get("severity", 999) > rule_sev:
            return False

    # Action check (e.g. FortiGate action=deny)
    rule_action = rule.get("action")
    if rule_action and rule_action.strip():
        parsed_data = log_item.get("parsed_json", {})
        log_action = parsed_data.get("action", "") or ""
        if log_action.lower() != rule_action.strip().lower():
            return False

    # Regex check on raw or message
    rule_regex = rule.get("filter_regex")
    if rule_regex and rule_regex.strip():
        try:
            pattern = re.compile(rule_regex.strip(), re.IGNORECASE)
            if not (pattern.search(log_item.get("raw", "")) or pattern.search(log_item.get("message", ""))):
                return False
        except re.error:
            # If invalid regex, do not match
            return False

    return True

async def send_webhook_payload(target_url: str, payload: Dict[str, Any], rule_name: str):
    """Asynchronous non-blocking HTTP POST dispatch."""
    client = get_http_client()
    try:
        response = await client.post(
            target_url,
            json=payload,
            headers={"Content-Type": "application/json", "User-Agent": "SyslogAggregator/1.0"}
        )
        logger.debug("Webhook [%s] sent to %s -> Status %d", rule_name, target_url, response.status_code)
    except Exception as e:
        logger.warning("Webhook [%s] failed to POST %s: %s", rule_name, target_url, e)

async def evaluate_and_dispatch_webhooks(batch: List[Dict[str, Any]]):
    """
    Evaluates incoming logs against all active webhook rules and fires dispatches.
    Uses asyncio.create_task for fire-and-forget execution.
    """
    rules = await get_all_webhooks()
    active_rules = [r for r in rules if r.get("enabled", 1)]
    if not active_rules:
        return

    for item in batch:
        for rule in active_rules:
            if matches_rule(item, rule):
                # Normalized payload requested in specification:
                # { "device": "10.0.0.1", "vendor": "cisco", "timestamp": "...", "severity": 3, "data": { ...parsed_fields... } }
                payload = {
                    "device": item.get("source_ip"),
                    "vendor": item.get("vendor_type"),
                    "timestamp": item.get("timestamp"),
                    "severity": item.get("severity"),
                    "facility": item.get("facility"),
                    "tag": item.get("tag"),
                    "mnemonic": item.get("mnemonic"),
                    "data": item.get("parsed_json", {}),
                    "raw": item.get("raw")
                }
                # Fire and forget task
                asyncio.create_task(send_webhook_payload(rule["target_url"], payload, rule["name"]))
