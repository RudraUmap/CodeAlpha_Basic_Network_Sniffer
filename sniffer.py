#!/usr/bin/env python3
"""
Network Packet Sniffer
-----------------------
A simple Python tool that captures live network traffic and displays
useful information about each packet: source/destination IP, protocol,
ports, and payload data.

Built with scapy. Must be run with administrator/root privileges.

Usage:
    sudo python3 sniffer.py
    sudo python3 sniffer.py -i eth0
    sudo python3 sniffer.py -f "tcp port 80"
    sudo python3 sniffer.py -c 50
    sudo python3 sniffer.py -o capture_log.txt
"""

import argparse
import sys
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

# Optional output file handle (set in main())
log_file = None


def log(message):
    """Print to console and optionally write to a log file."""
    print(message)
    if log_file:
        log_file.write(message + "\n")


def get_protocol_name(packet):
    """Return a human-readable protocol name for the packet."""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return "OTHER"


def process_packet(packet):
    """Callback executed for every captured packet."""
    if not packet.haslayer(IP):
        return

    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    protocol = get_protocol_name(packet)
    timestamp = datetime.now().strftime("%H:%M:%S")

    log("=" * 60)
    log(f"Time           : {timestamp}")
    log(f"Source IP      : {src_ip}")
    log(f"Destination IP : {dst_ip}")
    log(f"Protocol       : {protocol}")

    if packet.haslayer(TCP):
        log(f"Source Port    : {packet[TCP].sport}")
        log(f"Dest Port      : {packet[TCP].dport}")
        log(f"Flags          : {packet[TCP].flags}")
    elif packet.haslayer(UDP):
        log(f"Source Port    : {packet[UDP].sport}")
        log(f"Dest Port      : {packet[UDP].dport}")
    elif packet.haslayer(ICMP):
        log(f"ICMP Type      : {packet[ICMP].type}")

    if packet.haslayer(Raw):
        payload = packet[Raw].load
        try:
            decoded = payload.decode("utf-8", errors="replace")
            log(f"Payload (text) : {decoded[:100]}")
        except Exception:
            log(f"Payload (hex)  : {payload.hex()[:100]}")

    log("=" * 60 + "\n")


def parse_args():
    parser = argparse.ArgumentParser(
        description="A simple Python network packet sniffer built with scapy."
    )
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to sniff on (default: scapy's default interface)",
        default=None,
    )
    parser.add_argument(
        "-f", "--filter",
        help='BPF filter string, e.g. "tcp port 80" or "icmp"',
        default=None,
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture (default: 0 = infinite, stop with Ctrl+C)",
    )
    parser.add_argument(
        "-o", "--output",
        help="File path to save captured packet details as a text log",
        default=None,
    )
    return parser.parse_args()


def main():
    global log_file
    args = parse_args()

    if args.output:
        log_file = open(args.output, "a", encoding="utf-8")
        log(f"\n--- Capture started {datetime.now()} ---\n")

    print("Starting packet capture... Press Ctrl+C to stop.\n")
    if args.interface:
        print(f"Interface : {args.interface}")
    if args.filter:
        print(f"Filter    : {args.filter}")
    if args.count:
        print(f"Limit     : {args.count} packets")
    print()

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=process_packet,
            store=False,
            count=args.count,
        )
    except PermissionError:
        print("Permission denied: try running with sudo / as Administrator.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    finally:
        if log_file:
            log_file.close()


if __name__ == "__main__":
    main()
