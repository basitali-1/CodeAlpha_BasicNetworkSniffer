"""
CodeAlpha Internship - Task 1: Basic Network Sniffer
=====================================================
Author  : [Your Name]
Tool    : Python + Scapy
Purpose : Capture and analyze live network packets,
          displaying source/destination IPs, protocols, and payloads.

Requirements:
    pip install scapy
    Run with sudo/admin privileges (required for raw packet capture)
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime


# ─────────────────────────────────────────────
# CONFIG — change these as needed
# ─────────────────────────────────────────────
INTERFACE    = None   # Set to e.g. "eth0" or "Wi-Fi"; None = auto-detect
PACKET_LIMIT = 50     # How many packets to capture (0 = unlimited)
SHOW_PAYLOAD = True   # Set False to hide raw payload data


# ─────────────────────────────────────────────
# Protocol map: number → name
# ─────────────────────────────────────────────
PROTOCOL_MAP = {
    1:  "ICMP",
    6:  "TCP",
    17: "UDP",
}


def get_protocol_name(proto_num: int) -> str:
    """Return a human-readable protocol name."""
    return PROTOCOL_MAP.get(proto_num, f"OTHER({proto_num})")


def format_payload(raw_data: bytes, max_bytes: int = 64) -> str:
    """
    Try to decode payload as UTF-8 text.
    Fall back to a hex representation if it contains binary data.
    """
    try:
        decoded = raw_data[:max_bytes].decode("utf-8", errors="strict")
        return repr(decoded)
    except UnicodeDecodeError:
        return raw_data[:max_bytes].hex()


def packet_callback(packet):
    """Called automatically for every captured packet."""

    # We only care about IP packets
    if not packet.haslayer(IP):
        return

    ip_layer  = packet[IP]
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    protocol  = get_protocol_name(ip_layer.proto)
    src_ip    = ip_layer.src
    dst_ip    = ip_layer.dst
    pkt_len   = len(packet)

    print(f"\n{'─'*60}")
    print(f"  ⏱  Time     : {timestamp}")
    print(f"  📡 Protocol : {protocol}")
    print(f"  🔵 Source   : {src_ip}")
    print(f"  🔴 Dest     : {dst_ip}")
    print(f"  📦 Length   : {pkt_len} bytes")

    # ── TCP details ──────────────────────────────────────────
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        flags = tcp.sprintf("%flags%")   # e.g. "SA", "PA", "F"
        print(f"  🔌 Src Port : {tcp.sport}  →  Dst Port: {tcp.dport}")
        print(f"  🚩 Flags    : {flags}")

    # ── UDP details ──────────────────────────────────────────
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        print(f"  🔌 Src Port : {udp.sport}  →  Dst Port: {udp.dport}")

    # ── ICMP details ─────────────────────────────────────────
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable"}
        icmp_name  = icmp_types.get(icmp.type, f"Type {icmp.type}")
        print(f"  📨 ICMP Type: {icmp_name}")

    # ── Payload ──────────────────────────────────────────────
    if SHOW_PAYLOAD and packet.haslayer(Raw):
        payload_str = format_payload(packet[Raw].load)
        print(f"  📝 Payload  : {payload_str}")


def start_sniffer():
    """Start capturing packets on the specified interface."""
    print("=" * 60)
    print("   CodeAlpha — Basic Network Sniffer")
    print("=" * 60)
    print(f"  Interface : {INTERFACE or 'Auto-detect'}")
    print(f"  Limit     : {PACKET_LIMIT if PACKET_LIMIT > 0 else 'Unlimited'} packets")
    print(f"  Payload   : {'Shown' if SHOW_PAYLOAD else 'Hidden'}")
    print("=" * 60)
    print("  Press Ctrl+C to stop at any time.\n")

    try:
        sniff(
            iface=INTERFACE,
            prn=packet_callback,        # function called per packet
            count=PACKET_LIMIT,         # 0 = sniff forever
            store=False,                # don't keep packets in RAM
            filter="ip",               # only capture IP packets (BPF filter)
        )
    except PermissionError:
        print("\n[ERROR] Permission denied — please run with sudo or as Administrator.")
    except KeyboardInterrupt:
        print("\n\n[INFO] Sniffer stopped by user.")
    finally:
        print("[INFO] Capture complete.")


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    start_sniffer()
