from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

# ─────────────────────────────────────────
# Protocol map
# ─────────────────────────────────────────
PROTO_MAP = {6: "TCP", 17: "UDP", 1: "ICMP"}

def get_payload(packet):
    """Extract payload text if available."""
    if Raw in packet:
        try:
            return packet[Raw].load.decode("utf-8", errors="ignore")[:80]
        except Exception:
            return "[binary data]"
    return "No payload"

def packet_callback(packet):
    """Called for every captured packet."""
    if IP not in packet:
        return  # Skip non-IP packets

    timestamp = datetime.now().strftime("%H:%M:%S")
    src_ip    = packet[IP].src
    dst_ip    = packet[IP].dst
    proto_num = packet[IP].proto
    proto     = PROTO_MAP.get(proto_num, f"OTHER({proto_num})")

    print(f"\n[{timestamp}] Protocol: {proto}")
    print(f"  SRC IP : {src_ip}")
    print(f"  DST IP : {dst_ip}")

    # ── TCP details ──────────────────────
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags    = packet[TCP].flags
        print(f"  SRC Port: {src_port}  →  DST Port: {dst_port}")
        print(f"  TCP Flags: {flags}")

    # ── UDP details ──────────────────────
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        print(f"  SRC Port: {src_port}  →  DST Port: {dst_port}")

    # ── ICMP details ─────────────────────
    elif ICMP in packet:
        icmp_type = packet[ICMP].type
        print(f"  ICMP Type: {icmp_type}")

    # ── Payload ──────────────────────────
    payload = get_payload(packet)
    print(f"  Payload  : {payload}")
    print("  " + "─" * 50)

# ─────────────────────────────────────────
# Main — Start Sniffing
# ─────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("       CodeAlpha — Basic Network Sniffer")
    print("       Capturing 50 packets... Press Ctrl+C to stop")
    print("=" * 55)

    sniff(
        prn=packet_callback,
        count=50,          # Capture 50 packets (change to 0 for unlimited)
        store=False        # Don't store packets in memory
    )

    print("\n[✓] Packet capture complete.")