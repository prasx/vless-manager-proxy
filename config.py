"""Централизованная конфигурация VLESS Manager.

Все пути, порты, интервалы и тюнинг-параметры в одном месте.
"""

from pathlib import Path
from zoneinfo import ZoneInfo

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "proxies.db"
SUBSCRIBE_FILE = BASE_DIR / "subscribe.txt"
DEFAULT_XRAY_CONFIG = BASE_DIR / "xray_config.json"
ETC_XRAY_CONFIG = Path("/etc/xray/config.json")

MOSCOW_TZ = ZoneInfo("Europe/Moscow")
UTC_TZ = ZoneInfo("UTC")

SOCKS_PORT = 1080
HTTP_PORT = 1081
API_PORT = 10085
API_LISTEN = "127.0.0.1"

CHECK_INTERVAL = 60
PROBE_INTERVAL = "30s"
REIMPORT_CYCLES = 60

TEST_WORKERS = 20

LOG_TRIM_EVERY = 500
LOG_KEEP = 2000
