#!/usr/bin/env python3
"""
NetScope - Network Latency & Traffic Analyzer  v2.0

Entry point.  Parses CLI arguments, validates them, starts the Scapy
sniffer in a background thread, then launches the Flask web server
(which blocks the main thread) serving the live dashboard and REST API.
"""

import argparse
import os
import sys
import threading

from config.presets import get_preset, list_presets
from core.database import init_db, create_session
from core.sniffer import Sniffer
from utils.helpers import validate_ip, auto_detect_interface


# ------------------------------------------------------------------ #
# Privilege check
# ------------------------------------------------------------------ #

def _check_privileges():
    """Scapy raw sockets require elevated privileges."""
    if os.name == "nt":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[ERROR] Run as Administrator.")
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            print("[ERROR] Run as root:  sudo python main.py ...")
            sys.exit(1)


# ------------------------------------------------------------------ #
# CLI argument parsing
# ------------------------------------------------------------------ #

def _parse_args():
    parser = argparse.ArgumentParser(
        description="NetScope - Real-time network latency & traffic analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  sudo python main.py --target 8.8.8.8 --protocol udp --port 53\n"
            "  sudo python main.py --mode general\n"
            "  sudo python main.py --game csgo --target 146.148.83.14\n"
            "  sudo python main.py --target 192.168.1.1 --mode general\n"
            "  sudo python main.py --preset google_dns --target 8.8.8.8\n"
            "  sudo python main.py --target 8.8.8.8 --protocol icmp\n"
        ),
    )
    parser.add_argument("--target", type=str, default=None,
                        help="IP address to monitor (required in specific mode)")
    parser.add_argument("--ip", type=str, default=None,
                        help="[deprecated] Alias for --target")
    parser.add_argument("--port", type=int, default=None,
                        help="Port number (optional - all ports if omitted)")
    parser.add_argument("--protocol", type=str, default="all",
                        choices=["tcp", "udp", "icmp", "all"],
                        help="Protocol filter (default: all)")
    parser.add_argument("--mode", type=str, default="specific",
                        choices=["specific", "general"],
                        help="specific = one IP:port, general = all traffic")
    parser.add_argument("--label", type=str, default="",
                        help="Human-readable label for this session")
    parser.add_argument("--alert-rtt", type=float, default=200.0,
                        help="RTT threshold (ms) for high-latency alerts")
    parser.add_argument("--game", type=str, default=None,
                        help=f"Game/network preset ({', '.join(list_presets())})")
    parser.add_argument("--preset", type=str, default=None,
                        help="Alias for --game")
    parser.add_argument("--interface", type=str, default=None,
                        help="Network interface (auto-detect if omitted)")
    parser.add_argument("--duration", type=int, default=0,
                        help="Capture duration in seconds. 0 = forever")
    parser.add_argument("--host", type=str, default="0.0.0.0",
                        help="Bind address (default: 0.0.0.0 for LAN access)")
    parser.add_argument("--web-port", type=int, default=5000,
                        help="Web server port (default: 5000)")
    parser.add_argument("--no-web", action="store_true",
                        help="Disable web server, print metrics to terminal only")
    parser.add_argument("--debug", action="store_true",
                        help="Enable hot-reload and debug mode for development")
    return parser.parse_args()


# ------------------------------------------------------------------ #
# Main
# ------------------------------------------------------------------ #

def main():
    _check_privileges()
    args = _parse_args()

    # Resolve --ip to --target (backward compat)
    target_ip = args.target or args.ip
    server_port = args.port
    protocol = args.protocol or "all"
    mode = args.mode or "specific"
    label = args.label or ""
    game_name = None

    # Resolve preset (--game or --preset)
    preset_key = args.game or args.preset
    if preset_key:
        preset = get_preset(preset_key)
        if preset is None:
            print(f"[ERROR] Unknown preset '{preset_key}'. "
                  f"Available: {', '.join(list_presets())}")
            sys.exit(1)
        game_name = preset["name"]
        if server_port is None:
            server_port = preset.get("port") or preset.get("default_port")
        if protocol == "all":
            protocol = preset.get("protocol", "all")
        if not label:
            label = game_name

    # Validate
    if mode == "specific" and args.no_web:
        if target_ip is None:
            if preset_key:
                print(f"\n  Preset '{preset_key}' selected but no --target given.")
                print("  Find your server IP while the app is running:\n")
                print("    Linux / Mac:  netstat -an | grep <port>")
                print("    Windows:      netstat -an | findstr <port>\n")
                print(f"  Then re-run:  sudo python main.py"
                      f" --preset {preset_key} --target <IP>\n")
                sys.exit(1)
            else:
                print("[ERROR] Provide --target <IP> or use --mode general.")
                sys.exit(1)

        if not validate_ip(target_ip):
            print(f"[ERROR] Invalid IP address: {target_ip}")
            sys.exit(1)

    # Interface
    interface = args.interface or auto_detect_interface()

    # Database
    conn = init_db()
    
    start_capture = False
    if mode == "general":
        start_capture = True
    elif mode == "specific" and target_ip is not None:
        start_capture = True
        
    sniffer = None
    session_id = ""
    bpf = "(idle)"

    if start_capture:
        session_id = create_session(
            conn, target_ip or "0.0.0.0", server_port,
            game_name=game_name, interface=interface,
            label=label, protocol=protocol, mode=mode,
        )

        # Sniffer
        sniffer = Sniffer(
            target_ip=target_ip,
            server_port=server_port,
            session_id=session_id,
            conn=conn,
            interface=interface,
            duration=args.duration,
            protocol=protocol,
            mode=mode,
            label=label,
            alert_rtt=args.alert_rtt,
        )

        sniffer_thread = threading.Thread(target=sniffer.start, daemon=True)
        sniffer_thread.start()

        from core.sniffer import build_bpf
        bpf = build_bpf(target_ip, server_port, protocol, mode)

    # Banner
    web_port = args.web_port or 5000

    print(f"""
----------------------------------------------------
      NetScope - Network Analyzer v2.0
----------------------------------------------------
  Mode:       {mode}
  Target:     {target_ip or 'ALL'}:{server_port or 'ALL'}
  Protocol:   {protocol.upper()}
  Label:      {label or 'N/A'}
  Interface:  {interface}
  Session:    {session_id}
  BPF Filter: {bpf or '(none - all traffic)'}
""")

    # --- Web server or terminal-only mode ---
    if args.no_web:
        print("  [INFO] Web server disabled. Metrics printed to terminal.")
        print("  Press Ctrl+C to stop.\n")
        try:
            if sniffer:
                sniffer_thread.join()
            else:
                while True:
                    import time
                    time.sleep(1)
        except KeyboardInterrupt:
            print("\n[INFO] Shutting down…")
            if sniffer:
                sniffer.stop()
        return

    # Start Flask web server (default)
    from api.routes import create_app
    flask_app = create_app(
        sniffer=sniffer,
        db_conn=conn,
        session_id=session_id,
        config=args,
    )

    display_host = "127.0.0.1" if args.host == "0.0.0.0" else args.host
    print(f"  Dashboard → http://{display_host}:{web_port}")
    print("  Press Ctrl+C to stop.\n")

    try:
        if args.debug:
            flask_app.run(
                host=args.host,
                port=web_port,
                debug=True,
                use_reloader=False,
            )
        else:
            # Proper production WSGI server instead of Flask's built-in dev server
            from waitress import serve
            serve(flask_app, host=args.host, port=web_port)
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down…")
        if sniffer:
            sniffer.stop()


if __name__ == "__main__":
    main()
