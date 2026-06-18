"""
Known game server presets.

Maps game name → configuration dict containing default port,
protocol, tick rate, and notes.
"""

GAME_PRESETS = {
    "csgo": {
        "name": "CS:GO / CS2",
        "default_port": 27015,
        "protocol": "UDP",
        "typical_tick_rate": 64,
        "notes": "Use net_graph 1 in-game to verify connection",
    },
    "minecraft": {
        "name": "Minecraft Java Edition",
        "default_port": 25565,
        "protocol": "TCP",
        "typical_tick_rate": 20,
        "notes": "Survival and creative servers",
    },
    "valorant": {
        "name": "Valorant",
        "default_port": 7086,
        "protocol": "UDP",
        "typical_tick_rate": 128,
        "notes": "Port range 7086-7087",
    },
    "fortnite": {
        "name": "Fortnite",
        "default_port": 9000,
        "protocol": "UDP",
        "typical_tick_rate": 30,
        "notes": "Port range 9000-9100",
    },
    "rocket_league": {
        "name": "Rocket League",
        "default_port": 7777,
        "protocol": "UDP",
        "typical_tick_rate": 120,
        "notes": "",
    },
    "apex": {
        "name": "Apex Legends",
        "default_port": 37015,
        "protocol": "UDP",
        "typical_tick_rate": 60,
        "notes": "",
    },
}


def get_preset(game_name: str) -> dict | None:
    """Case-insensitive lookup. Returns None if not found."""
    return GAME_PRESETS.get(game_name.lower().replace(" ", "_"))


def list_presets() -> list[str]:
    """Return all known game preset keys."""
    return list(GAME_PRESETS.keys())
