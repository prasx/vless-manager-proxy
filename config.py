"""Централизованная конфигурация VLESS Manager.

Все пути, порты, интервалы и тюнинг-параметры в одном месте.
"""

from pathlib import Path
from zoneinfo import ZoneInfo

# ─── Пути ─────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent  # Корень проекта
DATABASE = BASE_DIR / "proxies.db"  # Файл SQLite БД
SUBSCRIBE_FILE = BASE_DIR / "subscribe.txt"  # Кеш подписки для внешних клиентов
DEFAULT_XRAY_CONFIG = (
    BASE_DIR / "xray_config.json"
)  # Локальный конфиг Xray (если нет systemd)
ETC_XRAY_CONFIG = Path("/etc/xray/config.json")  # systemd-конфиг Xray

# ─── Часовые пояса ────────────────────────────────────
MOSCOW_TZ = ZoneInfo("Europe/Moscow")  # Для отображения времени в UI
UTC_TZ = ZoneInfo("UTC")  # Для хранения в БД

# ─── Порты Xray ───────────────────────────────────────
SOCKS_PORT = 1080  # SOCKS5 inbound (для клиентов)
HTTP_PORT = 1081  # HTTP inbound
API_PORT = 10085  # gRPC API Xray (add/remove outbound)
API_LISTEN = "127.0.0.1"  # Слушать API только на localhost

# ─── Фоновый чекер ────────────────────────────────────
PROBE_INTERVAL = "20s"  # Интервал Observatory в конфиге Xray

# ─── Логирование ──────────────────────────────────────
LOG_TRIM_EVERY = 500  # Чистить логи каждые N записей
LOG_KEEP = 2000  # Оставлять последние N записей после чистки
