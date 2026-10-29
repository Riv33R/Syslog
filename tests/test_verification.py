import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import asyncio
from app.parsers import parse_syslog_message
from app.storage import init_registry_db, insert_logs_batch, query_device_logs, get_all_devices
from app.webhooks import matches_rule
from app.forwarder import (
    create_forwarding_endpoint,
    get_all_forwarding_endpoints,
    matches_endpoint,
    delete_forwarding_endpoint,
    test_endpoint_dispatch,
)

async def main():
    print("[1] Testing Parsers...")
    # Cisco
    cisco = parse_syslog_message("<189>%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down", "10.0.0.1")
    assert cisco["vendor_type"] == "cisco"
    assert cisco["severity"] == 3
    assert cisco["mnemonic"] == "UPDOWN"
    assert cisco["parsed_json"]["cisco_facility"] == "LINK"
    print("  [OK] Cisco parser passed")

    # FortiGate
    fg_raw = '<189>date=2026-10-29 time=11:00:00 devname="FW-01" type="traffic" subtype="forward" level="warning" srcip=192.168.1.1 dstip=8.8.8.8 action="deny" msg="Firewall block"'
    fg = parse_syslog_message(fg_raw, "10.0.0.2")
    assert fg["vendor_type"] == "fortigate"
    assert fg["severity"] == 4  # warning mapped to 4
    assert fg["parsed_json"]["action"] == "deny"
    assert fg["parsed_json"]["srcip"] == "192.168.1.1"
    print("  [OK] FortiGate parser passed")

    # Linux
    lx_raw = "<86>Oct 29 11:00:00 srv-01 sshd[24512]: Failed password for invalid user admin from 192.168.1.50 port 44322 ssh2"
    lx = parse_syslog_message(lx_raw, "10.0.0.3")
    assert lx["vendor_type"] == "linux"
    assert lx["parsed_json"]["app"] == "sshd"
    assert lx["parsed_json"]["pid"] == 24512
    print("  [OK] Linux parser passed")

    # Storage & DB Isolation
    print("[2] Testing Storage & Per-Device SQLite Isolation...")
    await init_registry_db()
    batch = [cisco, fg, lx]
    await insert_logs_batch(batch)

    # Check devices in registry
    devices = await get_all_devices()
    ips = [d["ip"] for d in devices]
    assert "10.0.0.1" in ips
    assert "10.0.0.2" in ips
    assert "10.0.0.3" in ips
    print(f"  [OK] Registry updated: {len(devices)} devices recorded")

    # Query Cisco isolated DB
    cisco_logs, total = await query_device_logs("10.0.0.1", limit=10)
    assert total >= 1
    assert cisco_logs[0]["vendor_type"] == "cisco"
    assert cisco_logs[0]["mnemonic"] == "UPDOWN"
    print(f"  [OK] Isolated device query passed: {total} log(s) for 10.0.0.1")

    # Webhook rules
    print("[3] Testing Webhook Rules...")
    rule_deny = {"enabled": 1, "vendor": "fortigate", "action": "deny", "max_severity": None, "filter_regex": None}
    assert matches_rule(fg, rule_deny) is True
    assert matches_rule(cisco, rule_deny) is False

    rule_sev = {"enabled": 1, "vendor": None, "action": None, "max_severity": 3, "filter_regex": None}
    assert matches_rule(cisco, rule_sev) is True  # Cisco sev is 3 <= 3
    assert matches_rule(fg, rule_sev) is False    # FG sev is 4 > 3
    print("  [OK] Webhook rule matching passed")

    # Forwarding Endpoints & Routing
    print("[4] Testing Forwarding Endpoints & Device Routing...")
    ep_id = await create_forwarding_endpoint(
        name="Test SIEM UDP",
        target_type="syslog_udp",
        host="127.0.0.1",
        port=1514,
        filter_source_ip="10.0.0.1",
        filter_vendor="cisco",
        filter_max_severity=3,
        forward_format="raw"
    )
    assert ep_id > 0
    endpoints = await get_all_forwarding_endpoints()
    assert any(e["id"] == ep_id for e in endpoints)

    ep_dict = next(e for e in endpoints if e["id"] == ep_id)
    assert matches_endpoint(cisco, ep_dict) is True
    assert matches_endpoint(fg, ep_dict) is False  # FG source is 10.0.0.2 != 10.0.0.1

    # Test probe dispatch
    probe_res = await test_endpoint_dispatch("syslog_udp", "127.0.0.1", 1514, "raw")
    assert probe_res["success"] is True

    await delete_forwarding_endpoint(ep_id)
    print("  [OK] Forwarding endpoints & routing tests passed")

    print("\nALL SYSTEM TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    asyncio.run(main())
