"""
Network target presets for NetScope v2.

Maps preset name → configuration dict containing port, protocol,
and human-readable name.  Includes both game server presets and
general network target presets.
"""

PRESETS = {
    # ─────────── Game Servers ─────────── #
    "csgo": {
        "name": "CS:GO / CS2",
        "port": 27015,
        "protocol": "udp",
        "notes": "Use net_graph 1 in-game to verify connection",
    },
    "valorant": {
        "name": "Valorant",
        "port": 7086,
        "protocol": "udp",
        "notes": "Port range 7086-7087",
    },
    "minecraft": {
        "name": "Minecraft Java Edition",
        "port": 25565,
        "protocol": "tcp",
        "notes": "Survival and creative servers",
    },
    "fortnite": {
        "name": "Fortnite",
        "port": 9000,
        "protocol": "udp",
        "notes": "Port range 9000-9100",
    },
    "apex": {
        "name": "Apex Legends",
        "port": 37015,
        "protocol": "udp",
        "notes": "",
    },
    "rocket_league": {
        "name": "Rocket League",
        "port": 7777,
        "protocol": "udp",
        "notes": "",
    },

    # ─────────── General Network Targets ─────────── #
    "google_dns": {
        "name": "Google DNS",
        "port": 53,
        "protocol": "udp",
        "notes": "Google Public DNS (8.8.8.8)",
    },
    "cloudflare": {
        "name": "Cloudflare DNS",
        "port": 53,
        "protocol": "udp",
        "notes": "Cloudflare DNS (1.1.1.1)",
    },
    "http": {
        "name": "HTTP target",
        "port": 80,
        "protocol": "tcp",
        "notes": "Unencrypted web traffic",
    },
    "https": {
        "name": "HTTPS target",
        "port": 443,
        "protocol": "tcp",
        "notes": "Encrypted web traffic",
    },
    "ssh": {
        "name": "SSH target",
        "port": 22,
        "protocol": "tcp",
        "notes": "Secure Shell connections",
    },
    "ping": {
        "name": "ICMP Ping",
        "port": None,
        "protocol": "icmp",
        "notes": "ICMP Echo Request/Reply",
    },
    "dns": {
        "name": "DNS target",
        "port": 53,
        "protocol": "udp",
        "notes": "Generic DNS monitoring",
    },
}


def get_preset(name: str) -> dict | None:
    """Case-insensitive preset lookup.  Returns None if not found."""
    return PRESETS.get(name.lower().replace(" ", "_").replace("-", "_"))


def list_presets() -> list[str]:
    """Return all known preset keys."""
    return list(PRESETS.keys())
