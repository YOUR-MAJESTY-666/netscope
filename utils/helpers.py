"""
Small utility functions used across modules — NetScope v2.

Provides IP validation, BPF filter construction, interface detection,
and timestamp / RTT formatting helpers.
"""

import re
import time
import socket
from datetime import datetime


def validate_ip(ip: str) -> bool:
    """Returns True if *ip* is a valid IPv4 address."""
    try:
        socket.inet_aton(ip)
        return True
    except (socket.error, OSError):
        return False


def build_bpf_filter(server_ip: str, port: int | None = None,
                     protocol: str = "udp",
                     mode: str = "specific") -> str:
    """Build a Berkeley Packet Filter string for Scapy's ``sniff()``.

    v2: Supports protocol and mode parameters.

    Args:
        server_ip: Target IP address.
        port: Target port (None = all ports).
        protocol: "tcp", "udp", "icmp", or "all".
        mode: "specific" or "general".

    Returns:
        BPF filter string.
    """
    if mode == "general":
        if protocol == "all":
            return ""
        return protocol

    # Specific mode
    parts = []
    if protocol and protocol != "all" and protocol != "icmp":
        parts.append(protocol)
    if server_ip:
        parts.append(f"host {server_ip}")
    if port:
        parts.append(f"port {port}")
    if protocol == "icmp":
        return "icmp"

    return " and ".join(parts) if parts else ""


def auto_detect_interface() -> str:
    """Return the default network interface name via Scapy."""
    try:
        from scapy.config import conf
        return str(conf.iface)
    except Exception:
        return "unknown"


def format_rtt(rtt_ms: float | None) -> str:
    """Return a human-readable RTT string like ``'12.3 ms'``.

    Returns ``'N/A'`` when *rtt_ms* is ``None`` or ``0``.
    """
    if rtt_ms is None or rtt_ms == 0:
        return "N/A"
    return f"{rtt_ms:.1f} ms"


def timestamp_to_str(ts: float) -> str:
    """Convert a Unix epoch float to ``'HH:MM:SS.mmm'``."""
    dt = datetime.fromtimestamp(ts)
    return dt.strftime("%H:%M:%S") + f".{int(dt.microsecond / 1000):03d}"


def ms_since(ts: float) -> float:
    """Return the number of milliseconds elapsed since *ts*."""
    return (time.time() - ts) * 1000.0


def format_bytes(n: int) -> str:
    """Format a byte count into a human-readable string (KB, MB, GB)."""
    if n < 1024:
        return f"{n} B"
    elif n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    elif n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    return f"{n / (1024 * 1024 * 1024):.2f} GB"
