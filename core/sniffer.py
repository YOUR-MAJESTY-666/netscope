"""
Scapy packet capture loop (background thread) — NetScope v2.

Captures packets matching the configured BPF filter, feeds each through
``parser.parse_packet()``, updates the MetricsEngine, runs anomaly
detection, and stores results in the database.

v2 changes:
- General mode (capture all traffic, not just one server)
- Dynamic BPF filter (supports tcp/udp/icmp/all)
- Anomaly detection integration
- MetricsEngine integration
- Thread-safe get_stats() for Flask API
"""

import threading
import time

from core.parser import parse_packet
from core import database
from core.metrics import MetricsEngine, rolling_stats, packet_loss
from core.anomaly import AnomalyDetector
from utils.helpers import timestamp_to_str, format_rtt


def build_bpf(target_ip, port, protocol, mode):
    """Build a BPF (Berkeley Packet Filter) string for Scapy.

    Args:
        target_ip: IP address to filter (None in general mode).
        port: Port number to filter (None = all ports).
        protocol: "tcp", "udp", "icmp", or "all".
        mode: "specific" (filter to IP:port) or "general" (all traffic).

    Returns:
        str: BPF filter expression (empty string = capture everything).
    """
    if mode == "general":
        if protocol == "all":
            return ""           # capture everything
        return protocol         # e.g. "tcp" or "icmp"

    # Specific mode
    parts = []
    if protocol and protocol != "all" and protocol != "icmp":
        parts.append(protocol)
    if target_ip:
        parts.append(f"host {target_ip}")
    if port:
        parts.append(f"port {port}")
    if protocol == "icmp":
        return "icmp"

    return " and ".join(parts) if parts else ""


class Sniffer:
    """Scapy-based packet sniffer with anomaly detection and metrics."""

    def __init__(self, target_ip: str | None = None,
                 server_port: int | None = None,
                 session_id: str = "",
                 conn=None,
                 interface: str | None = None,
                 duration: int = 0,
                 protocol: str = "all",
                 mode: str = "specific",
                 label: str = "",
                 alert_rtt: float = 200.0,
                 # Backward-compatible alias
                 server_ip: str | None = None,
                 server_port_compat: int | None = None):
        """
        Args:
            target_ip: Target IP to monitor. Use server_ip as fallback.
            server_port: Port to filter on.
            session_id: UUID for this capture session.
            conn: SQLite connection.
            interface: Network interface name.
            duration: Seconds to run (0 = forever).
            protocol: "tcp", "udp", "icmp", or "all".
            mode: "specific" or "general".
            label: Human-readable session label.
            alert_rtt: RTT threshold (ms) for high-latency alerts.
            server_ip: Backward-compatible alias for target_ip.
        """
        self.target_ip = target_ip or server_ip
        self.server_port = server_port
        self.session_id = session_id
        self.conn = conn
        self.interface = interface
        self.duration = duration
        self.protocol = protocol.lower() if protocol else "all"
        self.mode = mode
        self.label = label
        self.alert_rtt = alert_rtt

        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        # Metrics engine
        self.metrics = MetricsEngine(target_ip=self.target_ip)

        # Anomaly detector
        self.anomaly = AnomalyDetector(
            alert_callback=self._on_alert,
        )

        # v1 backward-compat: sent tracking for direct RTT matching
        self._sent: dict[int, float] = {}
        self._total_sent = 0
        self._total_received = 0
        self._rtts: list[float] = []

        # Cleanup thread handle
        self._cleanup_thread: threading.Thread | None = None

        # Session start time
        self._start_time = time.time()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def start(self):
        """Start capturing packets.  Called from a daemon thread."""
        from scapy.all import sniff as scapy_sniff

        bpf = build_bpf(
            self.target_ip, self.server_port,
            self.protocol, self.mode,
        )

        # Start cleanup thread (expires old unacked packets every 5 s)
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True,
        )
        self._cleanup_thread.start()

        # Blocking Scapy sniff loop
        scapy_sniff(
            filter=bpf if bpf else None,
            iface=self.interface,
            prn=self._packet_handler,
            stop_filter=lambda _pkt: self._stop_event.is_set(),
            timeout=self.duration if self.duration > 0 else None,
            store=False,
        )

    def stop(self):
        """Signal the sniff loop to exit."""
        self._stop_event.set()

    def get_stats(self):
        """Return a JSON-serializable snapshot of current metrics.

        Thread-safe — delegates to MetricsEngine.get_snapshot().
        """
        snapshot = self.metrics.get_snapshot()
        # Add session metadata
        snapshot["session_start"] = self._start_time
        return snapshot

    # ------------------------------------------------------------------ #
    # Internal
    # ------------------------------------------------------------------ #

    def _packet_handler(self, pkt):
        """Called by Scapy for every captured packet."""
        parsed = parse_packet(pkt, self.target_ip)
        if parsed is None:
            return

        # Update metrics engine
        self.metrics.update(parsed)

        # Run anomaly detection
        alerts = self.anomaly.check(parsed)
        for alert in alerts:
            self.metrics.increment_alert_count()

        # v1-compatible RTT tracking for database writes
        if parsed["direction"] == "out":
            seq = parsed.get("seq")
            if seq and seq != 0:
                with self._lock:
                    self._sent[seq] = parsed["timestamp"]
                    self._total_sent += 1

        elif parsed["direction"] == "in":
            ack = parsed.get("ack")
            rtt_ms = None
            if ack and ack != 0:
                with self._lock:
                    sent_time = self._sent.pop(ack, None)
                    if sent_time is None:
                        # Try ack-1 (TCP convention)
                        sent_time = self._sent.pop(ack - 1, None)
                if sent_time is not None:
                    rtt_ms = (parsed["timestamp"] - sent_time) * 1000.0
                    self._total_received += 1

            if rtt_ms is not None and rtt_ms > 0:
                self._rtts.append(rtt_ms)
                # Also feed into metrics engine directly
                self.metrics.add_rtt_direct(parsed["timestamp"], rtt_ms)
                # Write to database
                if self.conn:
                    try:
                        database.insert_rtt(
                            self.conn,
                            self.session_id,
                            parsed["timestamp"],
                            rtt_ms,
                            parsed.get("src_ip", ""),
                            parsed.get("dst_ip", ""),
                            parsed.get("src_port", 0),
                            parsed.get("dst_port", 0),
                            parsed.get("payload_size", 0),
                            parsed.get("seq", 0),
                        )
                    except Exception:
                        pass  # non-critical — don't crash capture

                ts_str = timestamp_to_str(parsed["timestamp"])
                print(f"[{ts_str}] RTT={format_rtt(rtt_ms)}  "
                      f"src={parsed.get('src_ip', '?')}")

    def _on_alert(self, alert_dict):
        """Callback from AnomalyDetector when an alert fires."""
        severity = alert_dict.get("severity", "LOW")
        desc = alert_dict.get("description", "")
        print(f"[ALERT] [{severity}] {desc}")

        # Write to database
        if self.conn:
            try:
                database.write_alert(
                    self.conn, self.session_id, alert_dict,
                )
            except Exception:
                pass  # non-critical

    def _cleanup_loop(self):
        """Expire unacknowledged entries older than 5 seconds."""
        while not self._stop_event.is_set():
            time.sleep(5)
            cutoff = time.time() - 5.0
            with self._lock:
                expired = [
                    seq for seq, ts in self._sent.items() if ts < cutoff
                ]
                for seq in expired:
                    del self._sent[seq]
