import re
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple
from app.config import get_app_timezone

# PRI pattern: <PRI>
PRI_REGEX = re.compile(r"^<(\d{1,3})>(.*)$", re.DOTALL)

# Cisco pattern: %FACILITY-SEVERITY-MNEMONIC: Description
# e.g., %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down
# e.g., %SYS-5-CONFIG_I: Configured from console by admin on vty0
CISCO_REGEX = re.compile(r"%([A-Za-z0-9_]+)-([0-7])-([A-Za-z0-9_]+):\s*(.*)", re.DOTALL)

# Fortinet Key-Value pattern: key=value or key="quoted value"
FORTI_KV_REGEX = re.compile(r'([a-zA-Z0-9_\-]+)=(?:"([^"\\]*(?:\\.[^"\\]*)*)"|([^\s"]+))')

# Linux Process pattern: process_name[PID]: message
LINUX_REGEX = re.compile(r'(?:^|[\s:])([a-zA-Z0-9_\-./]+)\[(\d+)\]:\s*(.*)', re.DOTALL)

# RFC 3164 BSD timestamp header: Mmm dd hh:mm:ss
RFC3164_TS_REGEX = re.compile(r"^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+")

# Cisco sequence number / uptime timestamp: e.g. "123: *Mar  1 00:00:00.000: " or "*Oct 29 11:00:00.123: "
CISCO_PRE_TS_REGEX = re.compile(r"^(?:\d+:\s*)?(?:\*?[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+[A-Z]{3,4})?:\s*)+")

# FortiGate log severity mapping to standard Syslog (RFC 5424)
FORTI_LEVEL_MAP = {
    "emergency": 0,
    "alert": 1,
    "critical": 2,
    "error": 3,
    "warning": 4,
    "notice": 5,
    "notification": 5,
    "information": 6,
    "info": 6,
    "debug": 7,
}

SEVERITY_NAMES = {
    0: "Emergency",
    1: "Alert",
    2: "Critical",
    3: "Error",
    4: "Warning",
    5: "Notice",
    6: "Informational",
    7: "Debug"
}

FACILITY_NAMES = {
    0: "kernel", 1: "user", 2: "mail", 3: "daemon",
    4: "auth", 5: "syslog", 6: "lpr", 7: "news",
    8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7"
}

def extract_pri(raw: str) -> Tuple[int, int, str]:
    """
    Extracts PRI from <PRI> header.
    Returns (facility, severity, remaining_content).
    Default: facility=1 (user), severity=6 (informational).
    """
    match = PRI_REGEX.match(raw.strip())
    if match:
        pri = int(match.group(1))
        facility = pri >> 3
        severity = pri & 7
        return facility, severity, match.group(2).strip()
    return 1, 6, raw.strip()


def parse_cisco(content: str, default_sev: int) -> Optional[Dict[str, Any]]:
    """
    Parses Cisco IOS / IOS-XE / NX-OS log.
    Pattern: %FACILITY-SEVERITY-MNEMONIC: Description
    """
    match = CISCO_REGEX.search(content)
    if not match:
        return None

    fac_str = match.group(1).upper()
    sev_int = int(match.group(2))
    mnemonic = match.group(3).upper()
    description = match.group(4).strip()

    # Extract optional hostname or prefix before the % token
    prefix = content[:match.start()].strip()
    hostname = None

    # Clean Cisco timestamp/sequence if present in prefix
    cleaned_prefix = CISCO_PRE_TS_REGEX.sub("", prefix).strip()
    if cleaned_prefix:
        # e.g., "switch-01" or "2026 Oct 29 11:00:00 switch-01"
        tokens = cleaned_prefix.split()
        if tokens:
            candidate = tokens[-1].rstrip(":")
            # Avoid picking a timestamp or pure number as hostname
            if not re.match(r"^(\d+|\d{2}:\d{2}:\d{2}.*)$", candidate):
                hostname = candidate

    return {
        "vendor_type": "cisco",
        "severity": sev_int,  # Cisco severity overrides general PRI
        "tag": fac_str,
        "mnemonic": mnemonic,
        "hostname": hostname,
        "message": description,
        "parsed_json": {
            "vendor_type": "cisco",
            "cisco_facility": fac_str,
            "cisco_severity": sev_int,
            "cisco_severity_name": SEVERITY_NAMES.get(sev_int, "Unknown"),
            "mnemonic": mnemonic,
            "mnemonic_code": f"%{fac_str}-{sev_int}-{mnemonic}",
            "message": description,
            "header_prefix": prefix if prefix else None
        }
    }


def parse_fortigate(content: str, default_sev: int) -> Optional[Dict[str, Any]]:
    """
    Parses Fortinet (FortiGate / FortiOS) log.
    Identifies key=value pairs and maps level to standard severity.
    """
    # Quick check for FortiGate characteristics
    if not (("devname=" in content or "logid=" in content) and ("type=" in content or "srcip=" in content or "action=" in content)):
        return None

    matches = FORTI_KV_REGEX.findall(content)
    if not matches or len(matches) < 3:
        return None

    kv_dict: Dict[str, str] = {}
    for k, quoted_v, unquoted_v in matches:
        val = quoted_v if quoted_v != "" else unquoted_v
        kv_dict[k] = val

    # Severity mapping
    level_str = kv_dict.get("level", "").lower()
    sev = FORTI_LEVEL_MAP.get(level_str, default_sev)

    hostname = kv_dict.get("devname")
    log_type = kv_dict.get("type", "")
    subtype = kv_dict.get("subtype", "")
    tag = f"{log_type}/{subtype}".strip("/") if (log_type or subtype) else "fortigate"

    action = kv_dict.get("action")
    srcip = kv_dict.get("srcip")
    dstip = kv_dict.get("dstip")
    srcport = kv_dict.get("srcport")
    dstport = kv_dict.get("dstport")
    policyid = kv_dict.get("policyid") or kv_dict.get("polid")
    msg = kv_dict.get("msg") or f"{action or 'traffic'} {srcip or ''}:{srcport or ''} -> {dstip or ''}:{dstport or ''}"

    parsed_json = {
        "vendor_type": "fortigate",
        "action": action,
        "srcip": srcip,
        "dstip": dstip,
        "srcport": srcport,
        "dstport": dstport,
        "policyid": policyid,
        "msg": msg,
        "level": level_str,
        "type": log_type,
        "subtype": subtype,
        "devname": hostname,
        "devid": kv_dict.get("devid"),
        "raw_fields": kv_dict
    }

    return {
        "vendor_type": "fortigate",
        "severity": sev,
        "tag": tag,
        "mnemonic": action.upper() if action else None,
        "hostname": hostname,
        "message": msg,
        "parsed_json": parsed_json
    }


def parse_linux(content: str, default_sev: int) -> Optional[Dict[str, Any]]:
    """
    Parses Linux logs with process/PID tags: process_name[PID]: message
    (systemd-journald / rsyslog / auditd / sshd / sudo, etc.)
    """
    match = LINUX_REGEX.search(content)
    if not match:
        return None

    app = match.group(1).strip()
    pid_str = match.group(2)
    message = match.group(3).strip()

    try:
        pid = int(pid_str)
    except ValueError:
        pid = None

    # Check prefix for hostname
    prefix = content[:match.start()].strip()
    hostname = None
    if prefix:
        # Strip RFC 3164 timestamp if present
        clean_prefix = RFC3164_TS_REGEX.sub("", prefix).strip()
        tokens = clean_prefix.split()
        if tokens:
            candidate = tokens[-1].rstrip(":")
            if not re.match(r"^(\d+|\d{2}:\d{2}:\d{2}.*)$", candidate):
                hostname = candidate

    parsed_json = {
        "vendor_type": "linux",
        "app": app,
        "pid": pid,
        "message": message,
        "header_prefix": prefix if prefix else None
    }

    return {
        "vendor_type": "linux",
        "severity": default_sev,
        "tag": app,
        "mnemonic": None,
        "hostname": hostname,
        "message": message,
        "parsed_json": parsed_json
    }


def parse_generic(content: str, default_sev: int) -> Dict[str, Any]:
    """
    Fallback parser for generic Syslog RFC 3164 / 5424.
    """
    hostname = None
    tag = None
    message = content

    # RFC 3164 generic match: [Mmm dd hh:mm:ss] [host] [tag:] msg
    rfc3164 = re.match(
        r'^(?:[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+)?(?:([^\s:]+)\s+)?(?:([A-Za-z0-9_\-./]+):\s*)?(.*)$',
        content,
        re.DOTALL
    )
    if rfc3164:
        h, t, m = rfc3164.groups()
        if h and not t and m:
            hostname = h
            message = m
        else:
            hostname = h
            tag = t
            message = m if m else content
    else:
        message = content

    parsed_json = {
        "vendor_type": "generic",
        "tag": tag,
        "hostname": hostname,
        "message": message
    }

    return {
        "vendor_type": "generic",
        "severity": default_sev,
        "tag": tag,
        "mnemonic": None,
        "hostname": hostname,
        "message": message,
        "parsed_json": parsed_json
    }


def parse_syslog_message(raw_line: str, source_ip: str) -> Dict[str, Any]:
    """
    Main parsing pipeline:
    1. Extracts PRI (severity, facility).
    2. Runs specialized parsers in order: FortiGate -> Cisco -> Linux -> Generic.
    3. Returns normalized dictionary ready for storage, indexing, and forwarding.
    """
    facility, default_sev, content = extract_pri(raw_line)
    now_iso = datetime.now(get_app_timezone()).isoformat()

    # Pipeline execution
    result = parse_fortigate(content, default_sev)
    if not result:
        result = parse_cisco(content, default_sev)
    if not result:
        result = parse_linux(content, default_sev)
    if not result:
        result = parse_generic(content, default_sev)

    # Attach common normalized attributes
    result["timestamp"] = now_iso
    result["source_ip"] = source_ip
    result["facility"] = facility
    result["facility_name"] = FACILITY_NAMES.get(facility, "unknown")
    result["severity_name"] = SEVERITY_NAMES.get(result["severity"], "Unknown")
    result["raw"] = raw_line

    # Ensure parsed_json has source_ip and timestamp for webhooks and export
    result["parsed_json"]["source_ip"] = source_ip
    result["parsed_json"]["timestamp"] = now_iso
    result["parsed_json"]["severity"] = result["severity"]
    result["parsed_json"]["facility"] = facility

    return result
