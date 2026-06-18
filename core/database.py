"""
SQLite session storage for NetScope v2.

One session = one program run.  Every RTT measurement is stored as a row
in ``rtt_samples``.  Security alerts are stored in ``alerts``.
Query helpers are provided for the dashboard and API.

Thread safety
-------------
* The connection is opened with ``check_same_thread=False``.
* All writes are serialised through a module-level ``threading.Lock()``.
"""

import sqlite3
import threading
import time
import uuid

_write_lock = threading.Lock()

# Module-level connection, set by init_db() and shared across threads.
_conn: sqlite3.Connection | None = None


def init_db(db_path: str = "latency_sessions.db") -> sqlite3.Connection:
    """Create tables if they don't exist and return the connection.

    The connection is also stored in the module-level ``_conn`` variable
    so that other modules can import it directly.
    """
    global _conn
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row  # dict-like access
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id   TEXT PRIMARY KEY,
            server_ip    TEXT NOT NULL,
            server_port  INTEGER,
            game_name    TEXT,
            started_at   REAL NOT NULL,
            interface    TEXT,
            label        TEXT,
            protocol     TEXT,
            mode         TEXT
        );
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rtt_samples (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT NOT NULL,
            timestamp   REAL NOT NULL,
            rtt_ms      REAL NOT NULL,
            src_ip      TEXT,
            dst_ip      TEXT,
            src_port    INTEGER,
            dst_port    INTEGER,
            payload_len INTEGER,
            seq         INTEGER
        );
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT NOT NULL,
            timestamp   REAL NOT NULL,
            type        TEXT NOT NULL,
            severity    TEXT NOT NULL,
            description TEXT NOT NULL,
            src_ip      TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );
    """)
    conn.commit()
    _conn = conn
    return conn


def create_session(conn: sqlite3.Connection, server_ip: str,
                   server_port: int | None = None,
                   game_name: str | None = None,
                   interface: str | None = None,
                   label: str | None = None,
                   protocol: str | None = None,
                   mode: str | None = None) -> str:
    """Insert a new session row and return its UUID string."""
    session_id = str(uuid.uuid4())
    with _write_lock:
        conn.execute(
            "INSERT INTO sessions (session_id, server_ip, server_port, "
            "game_name, started_at, interface, label, protocol, mode) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (session_id, server_ip, server_port or 0, game_name,
             time.time(), interface, label, protocol, mode),
        )
        conn.commit()
    return session_id


def insert_rtt(conn: sqlite3.Connection, session_id: str, timestamp: float,
               rtt_ms: float, src_ip: str, dst_ip: str,
               src_port: int, dst_port: int, payload_len: int,
               seq: int) -> None:
    """Insert one RTT measurement row (parameterised query)."""
    with _write_lock:
        conn.execute(
            "INSERT INTO rtt_samples "
            "(session_id, timestamp, rtt_ms, src_ip, dst_ip, "
            " src_port, dst_port, payload_len, seq) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (session_id, timestamp, rtt_ms, src_ip, dst_ip,
             src_port, dst_port, payload_len, seq),
        )
        conn.commit()


# ------------------------------------------------------------------ #
# Alert Functions (v2)
# ------------------------------------------------------------------ #

def write_alert(conn: sqlite3.Connection, session_id: str,
                alert_dict: dict) -> None:
    """Insert one alert row from an alert dict.

    Expected keys in alert_dict: timestamp, type, severity,
    description, src_ip.
    """
    with _write_lock:
        conn.execute(
            "INSERT INTO alerts "
            "(session_id, timestamp, type, severity, description, src_ip) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (session_id, alert_dict["timestamp"], alert_dict["type"],
             alert_dict["severity"], alert_dict["description"],
             alert_dict.get("src_ip")),
        )
        conn.commit()


def get_recent_alerts(conn: sqlite3.Connection, session_id: str,
                      limit: int = 50) -> list[dict]:
    """Return the last *limit* alerts for *session_id*, newest first."""
    cursor = conn.execute(
        "SELECT id, timestamp, type, severity, description, src_ip "
        "FROM alerts WHERE session_id = ? "
        "ORDER BY timestamp DESC LIMIT ?",
        (session_id, limit),
    )
    return [dict(row) for row in cursor.fetchall()]


def clear_alerts(conn: sqlite3.Connection, session_id: str) -> None:
    """Delete all alerts for *session_id*."""
    with _write_lock:
        conn.execute(
            "DELETE FROM alerts WHERE session_id = ?",
            (session_id,),
        )
        conn.commit()


# ------------------------------------------------------------------ #
# Query Functions (v1 — kept for backward compatibility)
# ------------------------------------------------------------------ #

def fetch_recent_rtts(conn: sqlite3.Connection, session_id: str,
                      limit: int = 200) -> list[dict]:
    """Return the last *limit* RTT rows for *session_id*, oldest first."""
    cursor = conn.execute(
        "SELECT * FROM rtt_samples WHERE session_id = ? "
        "ORDER BY timestamp DESC LIMIT ?",
        (session_id, limit),
    )
    rows = [dict(row) for row in cursor.fetchall()]
    rows.reverse()  # oldest first
    return rows


def fetch_session_summary(conn: sqlite3.Connection,
                          session_id: str) -> dict:
    """Return min/max/avg/count aggregates for the session."""
    cursor = conn.execute(
        "SELECT min(rtt_ms) AS min_rtt, max(rtt_ms) AS max_rtt, "
        "avg(rtt_ms) AS avg_rtt, count(*) AS total "
        "FROM rtt_samples WHERE session_id = ?",
        (session_id,),
    )
    row = cursor.fetchone()
    if row is None:
        return {"min_rtt": 0, "max_rtt": 0, "avg_rtt": 0, "total": 0}
    return dict(row)


def fetch_all_sessions(conn: sqlite3.Connection) -> list[dict]:
    """Return all sessions, newest first."""
    cursor = conn.execute(
        "SELECT * FROM sessions ORDER BY started_at DESC"
    )
    return [dict(row) for row in cursor.fetchall()]
