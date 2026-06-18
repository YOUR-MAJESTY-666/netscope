"""
Packet field extraction for NetScope v2.

Given a raw Scapy packet, extract useful fields and return a clean
Python dict.  This module is a *pure data transformer* — it never
imports ``database`` and has no side effects.

v2 changes:
- Supports ICMP and ARP packets (not just TCP/UDP)
- Extracts tcp_flags, icmp_type, icmp_id
- General mode: works without a server_ip filter
- Reports both 'size' (total) and 'payload_size' (L4 payload)
"""

import struct


def parse_packet(pkt, target_ip: str | None = None) -> dict | None:
    """Extract fields from a Scapy packet.

    Returns a dict with keys:
        timestamp, src_ip, dst_ip, src_port, dst_port,
        protocol, size, payload_size, tcp_flags, seq, ack,
        icmp_type, icmp_id, direction, ttl

    Returns ``None`` on any parse error or if the packet has no
    IP/ARP layer.

    Args:
        pkt: Scapy packet object.
        target_ip: If set, direction is computed relative to this IP.
                   If None (general mode), direction is always "unknown".
    """
    try:
        from scapy.layers.inet import IP, UDP, TCP, ICMP
        from scapy.layers.l2 import ARP
        from scapy.packet import Raw

        # Initialise result dict with defaults
        result = {
            "timestamp": float(pkt.time),
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "protocol": "Other",
            "size": len(pkt),
            "payload_size": 0,
            "tcp_flags": None,
            "seq": None,
            "ack": None,
            "icmp_type": None,
            "icmp_id": None,
            "direction": "unknown",
            "ttl": None,
        }

        # ----- ARP packets ----- #
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            result["protocol"] = "ARP"
            result["src_ip"] = arp.psrc
            result["dst_ip"] = arp.pdst
            if target_ip:
                if result["dst_ip"] == target_ip:
                    result["direction"] = "out"
                elif result["src_ip"] == target_ip:
                    result["direction"] = "in"
            return result

        # ----- IP-based packets ----- #
        if not pkt.haslayer(IP):
            return None

        ip_layer = pkt[IP]
        result["src_ip"] = ip_layer.src
        result["dst_ip"] = ip_layer.dst
        result["ttl"] = ip_layer.ttl

        # Direction relative to target
        if target_ip:
            if result["dst_ip"] == target_ip:
                result["direction"] = "out"
            elif result["src_ip"] == target_ip:
                result["direction"] = "in"

        # ----- Protocol detection (priority order) ----- #

        # 1. ICMP
        if pkt.haslayer(ICMP):
            icmp_layer = pkt[ICMP]
            result["protocol"] = "ICMP"
            result["icmp_type"] = icmp_layer.type
            result["icmp_id"] = getattr(icmp_layer, "id", None)
            # Use ICMP id as seq for RTT matching
            if result["icmp_type"] == 8:  # Echo Request
                result["seq"] = result["icmp_id"]
            elif result["icmp_type"] == 0:  # Echo Reply
                result["ack"] = result["icmp_id"]
            # Payload
            if pkt.haslayer(Raw):
                result["payload_size"] = len(bytes(pkt[Raw].load))
            return result

        # 2. TCP
        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            result["protocol"] = "TCP"
            result["src_port"] = tcp_layer.sport
            result["dst_port"] = tcp_layer.dport
            result["seq"] = tcp_layer.seq
            result["ack"] = tcp_layer.ack

            # Decode TCP flags
            flags = tcp_layer.flags
            flag_str = ""
            if flags & 0x02:  # SYN
                flag_str += "S"
            if flags & 0x10:  # ACK
                flag_str += "A"
            if flags & 0x01:  # FIN
                flag_str += "F"
            if flags & 0x04:  # RST
                flag_str += "R"
            if flags & 0x08:  # PSH
                flag_str += "P"
            if flags & 0x20:  # URG
                flag_str += "U"
            result["tcp_flags"] = flag_str if flag_str else None

            # Payload
            if pkt.haslayer(Raw):
                result["payload_size"] = len(bytes(pkt[Raw].load))
            return result

        # 3. UDP
        if pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            result["protocol"] = "UDP"
            result["src_port"] = udp_layer.sport
            result["dst_port"] = udp_layer.dport

            # Payload
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                result["payload_size"] = len(payload)
                # Extract seq/ack from first 8 bytes of payload
                # (game protocol / application-level sequence numbers)
                if len(payload) >= 8:
                    seq_val, ack_val = struct.unpack("<II", payload[:8])
                    result["seq"] = seq_val
                    result["ack"] = ack_val
                elif len(payload) >= 4:
                    result["seq"] = struct.unpack("<I", payload[:4])[0]
            return result

        # 4. Other IP protocol
        return result

    except Exception:
        return None
