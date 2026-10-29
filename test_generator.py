#!/usr/bin/env python3
"""
Syslog Traffic Generator for Testing and Demonstration.
Simulates Cisco devices, FortiGate firewalls, and Linux servers sending syslog events over UDP or TCP.
"""

import sys
import time
import socket
import random
import argparse
from datetime import datetime

CISCO_LOGS = [
    "<189>123: *Oct 29 11:20:01.100: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down",
    "<189>124: *Oct 29 11:20:05.200: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to up",
    "<189>125: *Oct 29 11:20:10.300: %OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on GigabitEthernet0/0 from LOADING to FULL, Loading Done",
    "<187>126: *Oct 29 11:20:15.400: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: root] [Source: 192.168.100.45] [localport: 22] [Reason: Authentication Failed]",
    "<189>127: *Oct 29 11:20:20.500: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (192.168.1.50)",
    "<186>128: *Oct 29 11:20:25.600: %BGP-2-BACKOFF: BGP peer 172.16.1.1 is down (HoldTimer expired)",
]

FORTIGATE_LOGS = [
    '<189>date=2026-10-29 time=11:20:00 devname="FGT-EDGE-01" devid="FG100ETK18000000" eventtime=1698573600 logid="0000000013" type="traffic" subtype="forward" level="warning" vd="root" srcip=192.168.1.100 srcport=54321 srcintf="port1" dstip=198.51.100.5 dstport=443 dstintf="port2" polid=1 sessionid=12345 proto=6 action="deny" policyid=1 msg="Traffic denied by firewall policy"',
    '<189>date=2026-10-29 time=11:20:05 devname="FGT-EDGE-01" devid="FG100ETK18000000" eventtime=1698573605 logid="0000000014" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.10.10.25 srcport=43210 srcintf="port1" dstip=8.8.8.8 dstport=53 dstintf="port2" polid=2 sessionid=12346 proto=17 action="accept" policyid=2 msg="Traffic allowed"',
    '<186>date=2026-10-29 time=11:20:10 devname="FGT-DC-CORE" devid="FG500ETK19000111" eventtime=1698573610 logid="0100020000" type="utm" subtype="virus" level="critical" vd="root" srcip=172.16.5.40 srcport=49152 dstip=203.0.113.195 dstport=80 action="block" msg="Blocked malicious payload signature Win32/Trojan.Generic"',
    '<188>date=2026-10-29 time=11:20:15 devname="FGT-DC-CORE" devid="FG500ETK19000111" eventtime=1698573615 logid="0101037128" type="utm" subtype="ips" level="alert" vd="root" srcip=185.220.101.5 srcport=61234 dstip=10.0.0.10 dstport=22 action="drop" attack="SSH.Brute.Force" msg="Intrusion Prevention detected brute force pattern"',
]

LINUX_LOGS = [
    "<38>Oct 29 11:20:00 srv-prod-01 sshd[24512]: Failed password for invalid user admin from 192.168.1.50 port 44322 ssh2",
    "<38>Oct 29 11:20:02 srv-prod-01 sshd[24515]: Accepted publickey for devops from 10.0.1.20 port 52140 ssh2: RSA SHA256:abc123xyz",
    "<86>Oct 29 11:20:05 srv-app-02 sudo[18921]: pam_unix(sudo:session): session opened for user root by devops(uid=1000)",
    "<30>Oct 29 11:20:08 db-cluster-01 systemd[1]: Started PostgreSQL Database Server cluster.",
    "<14>Oct 29 11:20:12 k8s-worker-01 dockerd[4092]: Container a4b8c9d0 stopped successfully",
]

GENERIC_LOGS = [
    "<13>Oct 29 11:20:15 ups-smart-01 APC Smart-UPS 3000: On Battery power due to input voltage sag (198V)",
    "<14>Oct 29 11:20:18 pdu-rack-a PDU Rack A: Branch circuit 1 current threshold exceeded: 15.2A",
]

ALL_POOLS = [
    ("cisco", CISCO_LOGS),
    ("fortigate", FORTIGATE_LOGS),
    ("linux", LINUX_LOGS),
    ("generic", GENERIC_LOGS)
]


def send_udp(host: str, port: int, message: str):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(message.encode("utf-8"), (host, port))


def send_tcp(host: str, port: int, message: str):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        sock.sendall((message + "\n").encode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description="Syslog Test Stream Generator")
    parser.add_argument("--host", default="127.0.0.1", help="Target host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=514, help="Target port (default: 514 standard syslog, or 1514)")
    parser.add_argument("--proto", choices=["udp", "tcp"], default="udp", help="Protocol: udp or tcp (default: udp)")
    parser.add_argument("--count", type=int, default=20, help="Number of messages to send (0 = infinite)")
    parser.add_argument("--interval", type=float, default=0.2, help="Interval in seconds between logs (default: 0.2)")
    parser.add_argument("--vendor", choices=["all", "cisco", "fortigate", "linux", "generic"], default="all")

    args = parser.parse_args()

    print(f"[*] Starting Syslog Generator to {args.host}:{args.port}/{args.proto.upper()}")
    print(f"[*] Vendor: {args.vendor.upper()}, Count: {args.count or 'Infinite'}, Interval: {args.interval}s")

    sent = 0
    try:
        while True:
            if args.vendor == "all":
                vendor, pool = random.choice(ALL_POOLS)
            else:
                pool = next(p for v, p in ALL_POOLS if v == args.vendor)
                vendor = args.vendor

            msg = random.choice(pool)

            if args.proto == "udp":
                send_udp(args.host, args.port, msg)
            else:
                send_tcp(args.host, args.port, msg)

            sent += 1
            print(f"[{sent:04d}] [{vendor.upper()}] Sent: {msg[:85]}...")

            if args.count and sent >= args.count:
                break

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")
    print(f"[OK] Completed. Total sent: {sent}")


if __name__ == "__main__":
    main()
