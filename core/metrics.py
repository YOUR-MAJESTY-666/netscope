"""
Network metrics computation for NetScope v2.

Contains both:
- Pure math functions (v1 — kept for backward compatibility)
- MetricsEngine class (v2 — thread-safe, real-time state tracking)

The MetricsEngine maintains in-memory state updated by every captured
packet.  It provides ``get_snapshot()`` to produce a JSON-serializable
dict consumed by the Flask REST API.
"""

import math
import statistics
import threading
import time
from collections import deque


# ====================================================================== #
# v1 Pure Math Functions (backward-compatible)
# ====================================================================== #

def mean_rtt(samples: list[float]) -> float:
    """Arithmetic mean of RTT samples.

    Formula: sum(samples) / len(samples)

    Returns 0.0 if *samples* is empty.
    """
    if not samples:
        return 0.0
    return sum(samples) / len(samples)


def jitter(samples: list[float]) -> float:
    """Standard deviation (sample) of RTT samples, a.k.a. jitter.

    Formula: sqrt( sum((x - mean)^2) / (n - 1) )
    Uses ``statistics.stdev()``.

    Returns 0.0 if fewer than 2 samples.
    """
    if len(samples) < 2:
        return 0.0
    return statistics.stdev(samples)


def packet_loss(sent: int, received: int) -> float:
    """Packet loss percentage.

    Formula: (sent - received) / sent * 100

    Returns 0.0 if *sent* is 0.
    """
    if sent == 0:
        return 0.0
    return (sent - received) / sent * 100.0


def percentile(samples: list[float], p: float) -> float:
    """Return the *p*-th percentile of *samples*.

    *p* is in the range 0–100.

    Formula: sorted(samples)[ ceil(p/100 * n) - 1 ]

    Returns 0.0 if *samples* is empty.
    """
    if not samples:
        return 0.0
    sorted_s = sorted(samples)
    n = len(sorted_s)
    idx = math.ceil(p / 100.0 * n) - 1
    idx = max(0, min(idx, n - 1))
    return sorted_s[idx]


def classify_latency(rtt_ms: float) -> str:
    """Classify a single RTT value into a human-readable quality label.

    Thresholds:
        < 20 ms  → "Excellent"
        20–50 ms → "Good"
        50–100 ms → "Playable"
        100–200 ms → "Poor"
        > 200 ms → "Unplayable"
    """
    if rtt_ms < 20:
        return "Excellent"
    if rtt_ms < 50:
        return "Good"
    if rtt_ms < 100:
        return "Playable"
    if rtt_ms < 200:
        return "Poor"
    return "Unplayable"


def rolling_stats(samples: list[float], window: int = 30) -> dict:
    """Compute statistics over the last *window* samples only.

    Returns a dict with keys: ``mean``, ``jitter``, ``p95``, ``p99``.
    """
    recent = samples[-window:] if len(samples) > window else samples
    return {
        "mean": mean_rtt(recent),
        "jitter": jitter(recent),
        "p95": percentile(recent, 95),
        "p99": percentile(recent, 99),
    }


# ====================================================================== #
# v2 MetricsEngine — Thread-safe Real-time State
# ====================================================================== #

class MetricsEngine:
    """Thread-safe metrics accumulator for real-time packet analysis.

    Updated by the Sniffer for every captured packet.  The Flask API
    calls ``get_snapshot()`` to obtain a JSON-serializable copy of
    all current statistics.
    """

    RTT_SERIES_MAXLEN = 500
    BANDWIDTH_WINDOW = 1.0  # seconds between bandwidth recalculations

    def __init__(self, target_ip=None):
        self._lock = threading.Lock()
        self._target_ip = target_ip

        # Latency tracking
        self._rtt_series = deque(maxlen=self.RTT_SERIES_MAXLEN)
        self._rtt_current = 0.0
        self._rtt_mean = 0.0
        self._jitter = 0.0
        self._p95 = 0.0

        # Packet loss
        self._total_sent = 0
        self._total_received = 0
        self._packet_loss_pct = 0.0

        # Protocol distribution
        self._protocol_counts = {
            "TCP": 0, "UDP": 0, "ICMP": 0,
            "ARP": 0, "DNS": 0, "Other": 0,
        }

        # Bandwidth
        self._bytes_in = 0
        self._bytes_out = 0
        self._bps_in = 0.0
        self._bps_out = 0.0
        self._last_bw_calc = time.time()
        self._bw_bytes_in_window = 0
        self._bw_bytes_out_window = 0

        # Top talkers: {ip: {"in": bytes, "out": bytes, "packets": int}}
        self._top_talkers = {}

        # Packet counter
        self._total_packets = 0
        self._session_start = time.time()

        # RTT matching via seq/ack dict
        # {(src_ip, dst_ip, seq): send_timestamp}
        self._pending_rtts = {}

        # Alert count (updated externally by anomaly detector)
        self._alert_count = 0

    def update(self, pkt_dict):
        """Process a parsed packet dict and update all metrics.

        Args:
            pkt_dict: Dict from parser.parse_packet() with keys including
                      timestamp, src_ip, dst_ip, protocol, size, direction,
                      seq, ack, dst_port, etc.
        """
        with self._lock:
            self._total_packets += 1
            proto = pkt_dict.get("protocol", "Other")
            size = pkt_dict.get("size", 0)
            direction = pkt_dict.get("direction", "")
            src_ip = pkt_dict.get("src_ip", "")
            dst_ip = pkt_dict.get("dst_ip", "")
            dst_port = pkt_dict.get("dst_port")
            ts = pkt_dict.get("timestamp", time.time())

            # --- Protocol counts ---
            # Detect DNS specifically (UDP on port 53)
            if proto == "UDP" and dst_port == 53:
                self._protocol_counts["DNS"] += 1
            elif proto in self._protocol_counts:
                self._protocol_counts[proto] += 1
            else:
                self._protocol_counts["Other"] += 1

            # --- Bandwidth tracking ---
            if direction == "in":
                self._bytes_in += size
                self._bw_bytes_in_window += size
            elif direction == "out":
                self._bytes_out += size
                self._bw_bytes_out_window += size

            # Recalculate bandwidth every BANDWIDTH_WINDOW seconds
            elapsed = ts - self._last_bw_calc
            if elapsed >= self.BANDWIDTH_WINDOW:
                self._bps_in = self._bw_bytes_in_window / elapsed
                self._bps_out = self._bw_bytes_out_window / elapsed
                self._bw_bytes_in_window = 0
                self._bw_bytes_out_window = 0
                self._last_bw_calc = ts

            # --- Top talkers ---
            for ip in (src_ip, dst_ip):
                if ip and ip != "0.0.0.0":
                    if ip not in self._top_talkers:
                        self._top_talkers[ip] = {
                            "in": 0, "out": 0, "packets": 0,
                        }
            if src_ip in self._top_talkers:
                self._top_talkers[src_ip]["out"] += size
                self._top_talkers[src_ip]["packets"] += 1
            if dst_ip in self._top_talkers:
                self._top_talkers[dst_ip]["in"] += size

            # --- RTT matching ---
            seq = pkt_dict.get("seq")
            ack = pkt_dict.get("ack")

            if direction == "out" and seq is not None and seq != 0:
                self._pending_rtts[(src_ip, dst_ip, seq)] = ts
                self._total_sent += 1

            elif direction == "in" and ack is not None and ack != 0:
                # Try to match: incoming ack matches outgoing seq
                # For TCP: look up (dst_ip, src_ip, ack-1)
                # The server (src_ip of reply) was the dst of original
                lookup_key = (dst_ip, src_ip, ack - 1)
                sent_time = self._pending_rtts.pop(lookup_key, None)

                if sent_time is None:
                    # Also try exact ack match (some protocols)
                    lookup_key = (dst_ip, src_ip, ack)
                    sent_time = self._pending_rtts.pop(lookup_key, None)

                if sent_time is not None:
                    rtt_ms = (ts - sent_time) * 1000.0
                    if rtt_ms > 0:
                        self._rtt_current = rtt_ms
                        self._rtt_series.append({"t": ts, "rtt": rtt_ms})
                        self._total_received += 1

                        # Recompute rolling stats
                        recent_rtts = [p["rtt"] for p in self._rtt_series]
                        self._rtt_mean = mean_rtt(recent_rtts)
                        self._jitter = jitter(recent_rtts)
                        self._p95 = percentile(recent_rtts, 95)

            # Packet loss
            if self._total_sent > 0:
                self._packet_loss_pct = packet_loss(
                    self._total_sent, self._total_received
                )

            # Expire old pending RTTs (> 5 seconds old)
            cutoff = ts - 5.0
            expired = [
                k for k, v in self._pending_rtts.items() if v < cutoff
            ]
            for k in expired:
                del self._pending_rtts[k]

    def add_rtt_direct(self, timestamp, rtt_ms):
        """Directly add an RTT measurement (used by sniffer's own matching)."""
        with self._lock:
            self._rtt_current = rtt_ms
            self._rtt_series.append({"t": timestamp, "rtt": rtt_ms})

            recent_rtts = [p["rtt"] for p in self._rtt_series]
            self._rtt_mean = mean_rtt(recent_rtts)
            self._jitter = jitter(recent_rtts)
            self._p95 = percentile(recent_rtts, 95)

    def increment_alert_count(self):
        """Thread-safe alert count increment."""
        with self._lock:
            self._alert_count += 1

    def get_snapshot(self):
        """Return a JSON-serializable dict of all current statistics.

        Thread-safe — takes a snapshot under lock.
        """
        with self._lock:
            # Top talkers sorted by total bytes
            talkers_list = []
            for ip, data in self._top_talkers.items():
                talkers_list.append({
                    "ip": ip,
                    "bytes_in": data["in"],
                    "bytes_out": data["out"],
                    "packets": data["packets"],
                })
            talkers_list.sort(
                key=lambda t: t["bytes_in"] + t["bytes_out"],
                reverse=True,
            )

            return {
                "rtt_current": round(self._rtt_current, 2),
                "rtt_mean": round(self._rtt_mean, 2),
                "jitter": round(self._jitter, 2),
                "p95": round(self._p95, 2),
                "packet_loss_pct": round(self._packet_loss_pct, 2),
                "bytes_in": self._bytes_in,
                "bytes_out": self._bytes_out,
                "bps_in": round(self._bps_in, 2),
                "bps_out": round(self._bps_out, 2),
                "total_packets": self._total_packets,
                "protocol_counts": dict(self._protocol_counts),
                "top_talkers": talkers_list[:10],
                "rtt_series": list(self._rtt_series)[-200:],
                "alert_count": self._alert_count,
            }
