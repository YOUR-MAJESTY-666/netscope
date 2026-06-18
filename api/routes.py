"""
Flask REST API for NetScope v2.

Provides JSON endpoints for the web dashboard to poll metrics, alerts,
packets, and session status.  Also serves the static HTML dashboard.

Endpoints
---------
GET /               → serves web/templates/index.html
GET /api/status     → session metadata and uptime
GET /api/metrics    → real-time RTT, bandwidth, protocol counts, top talkers
GET /api/alerts     → security alert log
GET /api/packets    → recent packet details
GET /api/packets    → recent packet details
GET /api/presets    → list available game/network presets
POST /api/start     → start a new capture session
POST /api/stop      → stop the active capture session
POST /api/clear_alerts → clear alert log for current session
"""

import time

from flask import Flask, Blueprint, jsonify, request, render_template


def create_app(sniffer=None, db_conn=None, session_id="",
               config=None):
    """Factory function to create the Flask application.

    Args:
        sniffer: Sniffer instance with get_stats() method.
        db_conn: SQLite connection for alert queries.
        session_id: UUID of the current capture session.
        config: argparse Namespace with CLI args (target, port, etc.).

    Returns:
        Flask app instance, ready to run.
    """
    import os

    # Resolve paths for templates and static files
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    template_dir = os.path.join(base_dir, "web", "templates")
    static_dir = os.path.join(base_dir, "web", "static")

    app = Flask(
        __name__,
        template_folder=template_dir,
        static_folder=static_dir,
        static_url_path="/static",
    )

    # Store references in app config for route access
    app.config["SNIFFER"] = sniffer
    app.config["DB_CONN"] = db_conn
    app.config["SESSION_ID"] = session_id
    app.config["APP_CONFIG"] = config
    app.config["START_TIME"] = time.time()

    # Register routes
    api_bp = _create_blueprint()
    app.register_blueprint(api_bp)

    return app


def _create_blueprint():
    """Create the API Blueprint with all routes."""
    from flask import current_app

    bp = Blueprint("api", __name__)

    # -------------------------------------------------------------- #
    # GET / -> serve dashboard HTML
    # -------------------------------------------------------------- #
    @bp.route("/")
    def index():
        return render_template("index.html")

    # -------------------------------------------------------------- #
    # GET /api/status -> session metadata
    # -------------------------------------------------------------- #
    @bp.route("/api/status")
    def api_status():
        sniffer = current_app.config.get("SNIFFER")
        config = current_app.config.get("APP_CONFIG")
        start_time = current_app.config.get("START_TIME", time.time())

        if sniffer is None:
            return jsonify({"running": False}), 200

        target = ""
        port = None
        protocol = "all"
        label = ""

        if config:
            target = getattr(config, "target", "") or ""
            port = getattr(config, "port", None)
            protocol = getattr(config, "protocol", "all") or "all"
            label = getattr(config, "label", "") or ""

        return jsonify({
            "running": True,
            "session_id": current_app.config.get("SESSION_ID", ""),
            "target": target,
            "port": port,
            "protocol": protocol.upper(),
            "label": label,
            "uptime_seconds": round(time.time() - start_time, 1),
            "interface": getattr(config, "interface", "auto") or "auto",
        })

    # -------------------------------------------------------------- #
    # GET /api/metrics -> real-time metrics snapshot
    # -------------------------------------------------------------- #
    @bp.route("/api/metrics")
    def api_metrics():
        sniffer = current_app.config.get("SNIFFER")
        if sniffer is None:
            return jsonify({"error": "not running", "running": False}), 200

        snapshot = sniffer.get_stats()
        return jsonify(snapshot)

    # -------------------------------------------------------------- #
    # GET /api/alerts -> recent security alerts
    # -------------------------------------------------------------- #
    @bp.route("/api/alerts")
    def api_alerts():
        from core.database import get_recent_alerts

        db_conn = current_app.config.get("DB_CONN")
        session_id = current_app.config.get("SESSION_ID", "")

        if db_conn is None or session_id == "":
            return jsonify([]), 200

        limit = request.args.get("limit", 50, type=int)
        alerts = get_recent_alerts(db_conn, session_id, limit=limit)
        return jsonify(alerts)

    # -------------------------------------------------------------- #
    # GET /api/packets -> recent captured packet details
    # -------------------------------------------------------------- #
    @bp.route("/api/packets")
    def api_packets():
        from core.database import fetch_recent_rtts

        db_conn = current_app.config.get("DB_CONN")
        session_id = current_app.config.get("SESSION_ID", "")

        if db_conn is None or session_id == "":
            return jsonify([]), 200

        limit = request.args.get("limit", 100, type=int)
        rows = fetch_recent_rtts(db_conn, session_id, limit=limit)
        return jsonify(rows)

    # -------------------------------------------------------------- #
    # POST /api/clear_alerts -> clear alert log
    # -------------------------------------------------------------- #
    @bp.route("/api/clear_alerts", methods=["POST"])
    def api_clear_alerts():
        from core.database import clear_alerts

        db_conn = current_app.config.get("DB_CONN")
        session_id = current_app.config.get("SESSION_ID", "")

        if db_conn is None:
            return jsonify({"error": "not running"}), 503

        clear_alerts(db_conn, session_id)
        return jsonify({"ok": True})

    # -------------------------------------------------------------- #
    # GET /api/presets -> list presets
    # -------------------------------------------------------------- #
    @bp.route("/api/presets")
    def api_presets():
        from config.presets import PRESETS
        return jsonify(PRESETS)

    # -------------------------------------------------------------- #
    # POST /api/start -> start capture
    # -------------------------------------------------------------- #
    @bp.route("/api/start", methods=["POST"])
    def api_start():
        from core.sniffer import Sniffer
        from core.database import create_session
        import threading
        from flask import current_app

        data = request.get_json() or {}
        target = data.get("target", "")
        port = data.get("port")
        protocol = data.get("protocol", "all")
        mode = data.get("mode", "specific")
        label = data.get("label", "")
        preset_key = data.get("preset", "")

        # Stop existing
        old_sniffer = current_app.config.get("SNIFFER")
        if old_sniffer:
            old_sniffer.stop()

        db_conn = current_app.config.get("DB_CONN")
        if not db_conn:
            from core.database import init_db
            db_conn = init_db()
            current_app.config["DB_CONN"] = db_conn

        game_name = None
        if preset_key:
            from config.presets import get_preset
            preset = get_preset(preset_key)
            if preset:
                game_name = preset["name"]
                if not port:
                    port = preset.get("port") or preset.get("default_port")
                if protocol == "all":
                    protocol = preset.get("protocol", "all")
                if not label:
                    label = game_name

        if port != "" and port is not None:
            try:
                port = int(port)
            except ValueError:
                port = None
        else:
            port = None

        config = current_app.config.get("APP_CONFIG")
        interface = getattr(config, "interface", "auto") if config else "auto"
        if interface == "auto":
            from utils.helpers import auto_detect_interface
            interface = auto_detect_interface()

        # Update app config dummy object
        class DummyConfig:
            pass
        new_config = DummyConfig()
        new_config.target = target
        new_config.port = port
        new_config.protocol = protocol
        new_config.label = label
        new_config.interface = interface
        current_app.config["APP_CONFIG"] = new_config

        session_id = create_session(
            db_conn, target or "0.0.0.0", port,
            game_name=game_name, interface=interface,
            label=label, protocol=protocol, mode=mode,
        )

        sniffer = Sniffer(
            target_ip=target if target else None,
            server_port=port,
            session_id=session_id,
            conn=db_conn,
            interface=interface,
            duration=0,
            protocol=protocol,
            mode=mode,
            label=label,
        )
        sniffer_thread = threading.Thread(target=sniffer.start, daemon=True)
        sniffer_thread.start()

        current_app.config["SNIFFER"] = sniffer
        current_app.config["SESSION_ID"] = session_id
        current_app.config["START_TIME"] = time.time()

        return jsonify({"ok": True, "session_id": session_id})

    # -------------------------------------------------------------- #
    # POST /api/stop -> stop capture
    # -------------------------------------------------------------- #
    @bp.route("/api/stop", methods=["POST"])
    def api_stop():
        from flask import current_app
        sniffer = current_app.config.get("SNIFFER")
        if sniffer:
            sniffer.stop()
            current_app.config["SNIFFER"] = None
            current_app.config["SESSION_ID"] = ""
        return jsonify({"ok": True})

    return bp
