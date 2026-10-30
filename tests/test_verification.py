import os
import sys
import tempfile
import shutil
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Sandbox: isolate test storage in a temporary directory so production data is never polluted
_test_sandbox_dir = tempfile.mkdtemp(prefix="syslog_test_sandbox_")
os.environ["DATA_DIR"] = _test_sandbox_dir

import asyncio
import socket
from app.parsers import parse_syslog_message
from app.storage import (
    init_registry_db,
    insert_logs_batch,
    query_device_logs,
    query_all_devices_logs,
    get_all_devices,
    delete_device,
    purge_synthetic_test_devices,
)
from app.webhooks import matches_rule
from app.forwarder import (
    create_forwarding_endpoint,
    get_all_forwarding_endpoints,
    matches_endpoint,
    delete_forwarding_endpoint,
    test_endpoint_dispatch,
    extract_pri_severity,
    matches_raw_endpoint,
    dispatch_pre_parse_forwarding,
    refresh_endpoints_cache,
    get_cached_active_endpoints,
    get_tcp_sender,
    close_persistent_forwarders,
    forward_vendor_filtered_logs,
)

async def test_udp_receiver(port: int, received_list: list, stop_event: asyncio.Event):
    """Simple mock UDP receiver for verifying forwarder packets."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    sock.setblocking(False)

    while not stop_event.is_set():
        try:
            data, _ = await loop.sock_recvfrom(sock, 4096)
            received_list.append(data.decode("utf-8", errors="replace"))
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(0.01)
    sock.close()


async def test_tcp_receiver(port: int, received_list: list, stop_event: asyncio.Event):
    """Simple mock TCP receiver for verifying persistent TCP forwarder."""
    async def client_cb(reader, writer):
        while True:
            line = await reader.readline()
            if not line:
                break
            received_list.append(line.decode("utf-8", errors="replace").strip())
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(client_cb, "127.0.0.1", port)
    await stop_event.wait()
    server.close()
    await server.wait_closed()


async def main():
    print("=" * 60)
    print("RUNNING SYSLOG SYSTEM TEST SUITE (SANDBOX ISOLATED)")
    print("=" * 60)

    try:
        # 1. Parsers
        print("\n[1] Testing Specialized Vendor Parsers...")
        cisco = parse_syslog_message("<189>%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down", "10.0.0.1")
        assert cisco["vendor_type"] == "cisco"
        assert cisco["severity"] == 3
        assert cisco["mnemonic"] == "UPDOWN"
        assert cisco["parsed_json"]["cisco_facility"] == "LINK"
        print("  [OK] Cisco parser verified")

        fg_raw = '<189>date=2026-10-29 time=11:00:00 devname="FW-01" type="traffic" subtype="forward" level="warning" srcip=192.168.1.1 dstip=8.8.8.8 action="deny" msg="Firewall block"'
        fg = parse_syslog_message(fg_raw, "10.0.0.2")
        assert fg["vendor_type"] == "fortigate"
        assert fg["severity"] == 4  # warning mapped to 4
        assert fg["parsed_json"]["action"] == "deny"
        assert fg["parsed_json"]["srcip"] == "192.168.1.1"
        print("  [OK] FortiGate parser verified")

        lx_raw = "<86>Oct 29 11:00:00 srv-01 sshd[24512]: Failed password for invalid user admin from 192.168.1.50 port 44322 ssh2"
        lx = parse_syslog_message(lx_raw, "10.0.0.3")
        assert lx["vendor_type"] == "linux"
        assert lx["parsed_json"]["app"] == "sshd"
        assert lx["parsed_json"]["pid"] == 24512
        print("  [OK] Linux parser verified")

        # 2. Fast PRI Severity Extraction (Microsecond lane)
        print("\n[2] Testing Microsecond Fast PRI Extraction...")
        assert extract_pri_severity("<189>%LINK-3-UPDOWN: ...") == (189 & 7)  # 5
        assert extract_pri_severity("<86>sshd: ...") == (86 & 7)              # 6
        assert extract_pri_severity("<0>Kernel Panic!") == 0                  # 0 (Emergency)
        assert extract_pri_severity("Plain text without pri") == 6            # 6 (Default Informational)
        print("  [OK] extract_pri_severity passed for all RFC syslog formats")

        # 3. Storage & DB Isolation in Sandbox
        print("\n[3] Testing Storage & Per-Device SQLite Isolation...")
        await init_registry_db()
        batch = [cisco, fg, lx]
        await insert_logs_batch(batch)

        devices = await get_all_devices()
        ips = [d["ip"] for d in devices]
        assert "10.0.0.1" in ips
        assert "10.0.0.2" in ips
        assert "10.0.0.3" in ips
        print(f"  [OK] Registry updated in sandbox: {len(devices)} devices recorded")

        cisco_logs, total = await query_device_logs("10.0.0.1", limit=10)
        assert total >= 1
        assert cisco_logs[0]["vendor_type"] == "cisco"
        assert cisco_logs[0]["mnemonic"] == "UPDOWN"
        print(f"  [OK] Isolated per-device query verified: {total} log(s) for 10.0.0.1")

        # 4. Webhook rules
        print("\n[4] Testing Webhook Rules...")
        rule_deny = {"enabled": 1, "vendor": "fortigate", "action": "deny", "max_severity": None, "filter_regex": None}
        assert matches_rule(fg, rule_deny) is True
        assert matches_rule(cisco, rule_deny) is False

        rule_sev = {"enabled": 1, "vendor": None, "action": None, "max_severity": 3, "filter_regex": None}
        assert matches_rule(cisco, rule_sev) is True
        assert matches_rule(fg, rule_sev) is False
        print("  [OK] Webhook rule matching passed")

        # 5. Pre-Parse Fast Forwarding (Raw Wire Relay)
        print("\n[5] Testing Pre-Parse Fast Forwarding (Raw Wire Relay)...")
        test_udp_port = 19514
        received_udp = []
        stop_udp = asyncio.Event()
        udp_task = asyncio.create_task(test_udp_receiver(test_udp_port, received_udp, stop_udp))
        await asyncio.sleep(0.1)

        ep_id_udp = await create_forwarding_endpoint(
            name="Pre-Parse Test UDP",
            target_type="syslog_udp",
            host="127.0.0.1",
            port=test_udp_port,
            filter_source_ip="10.0.0.1",
            filter_vendor=None,
            filter_max_severity=5,
            forward_format="raw"
        )
        assert ep_id_udp > 0

        cached = get_cached_active_endpoints()
        assert any(e["id"] == ep_id_udp for e in cached)

        raw_cisco = "<189>%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down"
        raw_other = "<189>%LINK-3-UPDOWN: Message from different host"
        ep_dict = next(e for e in cached if e["id"] == ep_id_udp)

        assert matches_raw_endpoint("10.0.0.1", raw_cisco, ep_dict) is True
        assert matches_raw_endpoint("192.168.1.55", raw_other, ep_dict) is False

        dispatch_pre_parse_forwarding(raw_cisco, "10.0.0.1")
        await asyncio.sleep(0.1)

        assert len(received_udp) >= 1
        assert received_udp[-1] == raw_cisco
        print(f"  [OK] Pre-parse UDP packet forwarded verbatim: '{received_udp[-1][:40]}...'")

        stop_udp.set()
        udp_task.cancel()
        await delete_forwarding_endpoint(ep_id_udp)

        # 6. Persistent TCP Forwarding
        print("\n[6] Testing Persistent Keep-Alive TCP Forwarding...")
        test_tcp_port = 19515
        received_tcp = []
        stop_tcp = asyncio.Event()
        tcp_task = asyncio.create_task(test_tcp_receiver(test_tcp_port, received_tcp, stop_tcp))
        await asyncio.sleep(0.1)

        sender = get_tcp_sender("127.0.0.1", test_tcp_port)
        for i in range(5):
            msg = f"<14>Oct 30 12:00:0{i} srv-01 app: message {i}\n"
            ok = await sender.send(msg.encode("utf-8"))
            assert ok is True

        await asyncio.sleep(0.1)
        assert len(received_tcp) == 5
        print("  [OK] Persistent TCP sender streamed 5 messages over single keep-alive connection")

        await close_persistent_forwarders()
        stop_tcp.set()
        tcp_task.cancel()

        # 7. Post-Parse Vendor-Filtered Lane
        print("\n[7] Testing Post-Parse Vendor-Filtered Lane...")
        ep_id_vendor = await create_forwarding_endpoint(
            name="Cisco Only Filtered",
            target_type="syslog_udp",
            host="127.0.0.1",
            port=19516,
            filter_source_ip=None,
            filter_vendor="cisco",
            filter_max_severity=4,
            forward_format="raw"
        )
        v_cached = get_cached_active_endpoints()
        v_ep = next(e for e in v_cached if e["id"] == ep_id_vendor)

        assert matches_raw_endpoint("10.0.0.1", raw_cisco, v_ep) is False
        assert matches_endpoint(cisco, v_ep) is True
        assert matches_endpoint(fg, v_ep) is False
        print("  [OK] Vendor-specific rules correctly isolated to post-parse classification lane")

        await delete_forwarding_endpoint(ep_id_vendor)

        # 8. Test Probe API
        print("\n[8] Testing Test Probe Dispatch...")
        probe_res = await test_endpoint_dispatch("syslog_udp", "127.0.0.1", 1514, "raw")
        assert probe_res["success"] is True
        print("  [OK] Test probe dispatch verified")

        # 9. Device Deletion and Purge API
        print("\n[9] Testing Device Deletion & Test Data Purge...")
        all_devs_before = await get_all_devices()
        assert len(all_devs_before) >= 3
        # Test deleting specific device
        deleted = await delete_device("10.0.0.1")
        assert deleted is True
        all_devs_after = await get_all_devices()
        assert not any(d["ip"] == "10.0.0.1" for d in all_devs_after)
        print("  [OK] delete_device correctly removed device from registry & filesystem")

        # Test purge synthetic test devices
        purged = await purge_synthetic_test_devices()
        assert "10.0.0.2" in purged or "10.0.0.3" in purged
        all_devs_final = await get_all_devices()
        assert len(all_devs_final) == 0
        print("  [OK] purge_synthetic_test_devices successfully purged test devices")

        # 10. Parallel Cross-Device Query
        print("\n[10] Testing Parallel Cross-Device Query (asyncio.gather)...")
        # Insert logs across 5 devices
        sim_batch = []
        for i in range(5):
            sim_batch.append(parse_syslog_message(f"<189>%SYS-5-CONFIG: host-{i}", f"172.16.0.{i+1}"))
        await insert_logs_batch(sim_batch)
        cross_logs, cross_total = await query_all_devices_logs(limit=20)
        assert cross_total == 5
        assert len(cross_logs) == 5
        print(f"  [OK] Parallel cross-device query fetched {cross_total} logs correctly")

        print("\n" + "=" * 60)
        print("ALL 10 SYSTEM TEST SUITES PASSED IN ISOLATED SANDBOX!")
        print("=" * 60)

    finally:
        # Clean up temporary sandbox directory
        shutil.rmtree(_test_sandbox_dir, ignore_errors=True)

if __name__ == "__main__":
    asyncio.run(main())
