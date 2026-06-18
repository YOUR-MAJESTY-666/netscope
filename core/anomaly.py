"""
Anomaly detection engine for NetScope v2.

Stateless anomaly detector called with each parsed packet dict.
Maintains internal sliding windows for rate and port-scan detection.
Returns list of Alert dicts (may be empty).

Detection Rules
---------------
1. PORT_SCAN      — >10 unique dst_ports from same src_ip in 5s  (HIGH)
2. HIGH_RATE      — >500 packets/sec from single src_ip           (HIGH)
3. PROTO_MISMATCH — non-TCP on port 80, etc.                      (MEDIUM)
4. LARGE_UDP      — UDP payload > 1400 bytes                      (LOW)
5. ICMP_FLOOD     — >100 ICMP packets/sec from single src_ip      (HIGH)
"""

from collections import defaultdict, deque
import time
import threading


class AnomalyDetector:
    """Real-time anomaly detector for network packets."""

    # Detection thresholds
    PORT_SCAN_THRESHOLD = 10    # unique ports in window
    PORT_SCAN_WINDOW = 5.0      # seconds
    RATE_THRESHOLD = 500        # packets per second
    RATE_WINDOW = 1.0           # seconds
    ICMP_THRESHOLD = 100        # ICMP packets per second
    ICMP_WINDOW = 1.0           # seconds
    LARGE_UDP_BYTES = 1400      # bytes
    DEDUP_WINDOW = 10.0         # seconds between same alert type from same IP

    def __init__(self, alert_callback=None):
        """
        Args:
            alert_callback: Optional callable(alert_dict) invoked on each
                            new alert. Used to persist alerts to the database.
        """
        self.alert_callback = alert_callback

        # Port scan tracking: {src_ip: deque of (timestamp, dst_port)}
        self.port_contact_window = defaultdict(deque)

        # Packet rate tracking: {src_ip: deque of timestamps}
        self.pkt_rate_window = defaultdict(deque)

        # ICMP flood tracking: {src_ip: deque of timestamps}
        self.icmp_window = defaultdict(deque)

        # Deduplication: {(src_ip, alert_type): last_fire_timestamp}
        self._fired = {}
        self._fired_lock = threading.Lock()

    def check(self, pkt_dict):
        """Check a parsed packet dict against all anomaly rules.

        Args:
            pkt_dict: Dict from parser.parse_packet() with keys like
                      src_ip, dst_port, protocol, payload_size, timestamp.

        Returns:
            list[dict]: List of alert dicts (may be empty).
        """
        alerts = []
        now = pkt_dict.get("timestamp", time.time())
        src = pkt_dict.get("src_ip", "")
        dst_port = pkt_dict.get("dst_port")
        proto = pkt_dict.get("protocol", "")
        payload_size = pkt_dict.get("payload_size", 0)

        if not src:
            return alerts

        # --- Rule 1: Port scan detection ---
        if dst_port is not None:
            w = self.port_contact_window[src]
            w.append((now, dst_port))
            cutoff = now - self.PORT_SCAN_WINDOW
            while w and w[0][0] < cutoff:
                w.popleft()
            unique_ports = len(set(p for _, p in w))
            if unique_ports >= self.PORT_SCAN_THRESHOLD:
                alert = self._make_alert(
                    "PORT_SCAN", "HIGH",
                    f"{src} contacted {unique_ports} unique ports in "
                    f"{self.PORT_SCAN_WINDOW:.0f}s",
                    src, now,
                )
                if self._dedup(alert):
                    alerts.append(alert)

        # --- Rule 2: High packet rate ---
        w = self.pkt_rate_window[src]
        w.append(now)
        cutoff = now - self.RATE_WINDOW
        while w and w[0] < cutoff:
            w.popleft()
        if len(w) >= self.RATE_THRESHOLD:
            alert = self._make_alert(
                "HIGH_RATE", "HIGH",
                f"{src} sent {len(w)} packets in {self.RATE_WINDOW:.0f}s",
                src, now,
            )
            if self._dedup(alert):
                alerts.append(alert)

        # --- Rule 3: Protocol mismatch ---
        if dst_port == 80 and proto != "TCP":
            alert = self._make_alert(
                "PROTO_MISMATCH", "MEDIUM",
                f"Non-TCP traffic on port 80 from {src}",
                src, now,
            )
            if self._dedup(alert):
                alerts.append(alert)

        # --- Rule 4: Large UDP payload ---
        if proto == "UDP" and payload_size > self.LARGE_UDP_BYTES:
            alert = self._make_alert(
                "LARGE_UDP", "LOW",
                f"UDP payload {payload_size}B from {src} "
                f"(fragmentation risk)",
                src, now,
            )
            if self._dedup(alert):
                alerts.append(alert)

        # --- Rule 5: ICMP flood ---
        if proto == "ICMP":
            w = self.icmp_window[src]
            w.append(now)
            cutoff = now - self.ICMP_WINDOW
            while w and w[0] < cutoff:
                w.popleft()
            if len(w) >= self.ICMP_THRESHOLD:
                alert = self._make_alert(
                    "ICMP_FLOOD", "HIGH",
                    f"{src} sent {len(w)} ICMP packets in "
                    f"{self.ICMP_WINDOW:.0f}s",
                    src, now,
                )
                if self._dedup(alert):
                    alerts.append(alert)

        # Fire callback for each new alert
        if self.alert_callback:
            for a in alerts:
                self.alert_callback(a)

        return alerts

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _make_alert(self, alert_type, severity, description, src_ip, now=None):
        """Build a standardised alert dict."""
        return {
            "timestamp": now or time.time(),
            "type": alert_type,
            "severity": severity,
            "description": description,
            "src_ip": src_ip,
        }

    def _dedup(self, alert):
        """Return True if this alert should be emitted (not a duplicate).

        Suppresses duplicate (src_ip, type) combos within DEDUP_WINDOW seconds.
        Also lazily cleans up expired entries.
        """
        key = (alert["src_ip"], alert["type"])
        now = alert["timestamp"]

        with self._fired_lock:
            # Lazy cleanup of expired entries
            expired_keys = [
                k for k, ts in self._fired.items()
                if now - ts > self.DEDUP_WINDOW
            ]
            for k in expired_keys:
                del self._fired[k]

            if key in self._fired:
                return False
            self._fired[key] = now
            return True
