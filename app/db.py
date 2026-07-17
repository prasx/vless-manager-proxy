"""Работа с SQLite: инициализация схемы, запросы, настройки."""

import sqlite3
import time
from pathlib import Path

from config import DATABASE, ETC_XRAY_CONFIG, DEFAULT_XRAY_CONFIG


def _get_conn() -> sqlite3.Connection:
    """Создаёт и возвращает новое подключение к БД."""
    conn = sqlite3.connect(str(DATABASE), timeout=15)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA mmap_size=67108864")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=-4000")
    conn.row_factory = sqlite3.Row
    return conn


def db_q(sql: str, params: tuple | list = ()) -> list[sqlite3.Row]:
    """Выполняет SQL-запрос с параметрами, коммитит и возвращает результаты.
    При SQLITE_BUSY повторяет до 5 раз с экспоненциальной задержкой."""
    for attempt in range(5):
        conn = _get_conn()
        try:
            c = conn.cursor()
            c.execute(sql, params)
            conn.commit()
            return c.fetchall()
        except sqlite3.OperationalError as e:
            if "busy" in str(e).lower() and attempt < 4:
                time.sleep(0.1 * (2**attempt))
                continue
            raise
        finally:
            conn.close()


# Эталонная схема таблиц — все ожидаемые колонки и их типы
_SCHEMA = {
    "proxies": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("link", "TEXT UNIQUE"),
        ("host", "TEXT"),
        ("port", "INTEGER"),
        ("country", "TEXT"),
        ("country_verified", "INTEGER DEFAULT 0"),
        ("status", "TEXT DEFAULT 'pending'"),
        ("latency", "INTEGER DEFAULT 0"),
        ("added_at", "TIMESTAMP"),
        ("failed_since", "TIMESTAMP"),
        ("security", "TEXT DEFAULT ''"),
        ("latency_vless", "INTEGER DEFAULT 0"),
        ("speed_kbps", "INTEGER DEFAULT 0"),
        ("source_id", "INTEGER"),
    ],
    "sources": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("name", "TEXT"),
        ("url", "TEXT UNIQUE"),
        ("type", "TEXT DEFAULT 'url'"),
        ("content", "TEXT"),
        ("last_import", "TIMESTAMP"),
        ("created_at", "TIMESTAMP"),
    ],
    "logs": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("timestamp", "TIMESTAMP"),
        ("level", "TEXT"),
        ("message", "TEXT"),
        ("correlation_id", "TEXT"),
    ],
    "settings": [
        ("key", "TEXT PRIMARY KEY"),
        ("value", "TEXT"),
    ],
    "traffic_history": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("collected_at", "TEXT"),
        ("total_downlink", "INTEGER DEFAULT 0"),
        ("total_uplink", "INTEGER DEFAULT 0"),
        ("active_outbounds", "INTEGER DEFAULT 0"),
        ("active_connections", "INTEGER DEFAULT 0"),
    ],
}


def _ensure_schema(conn: sqlite3.Connection) -> None:
    """Проверяет эталонную схему и добавляет недостающие таблицы/колонки."""
    c = conn.cursor()
    for table, columns in _SCHEMA.items():
        cols_sql = ", ".join(f"{name} {typ}" for name, typ in columns)
        c.execute(f"CREATE TABLE IF NOT EXISTS {table} ({cols_sql})")
        existing = {
            row[1] for row in c.execute(f"PRAGMA table_info({table})").fetchall()
        }
        for col_name, col_type in columns:
            if col_name not in existing:
                try:
                    c.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}")
                except sqlite3.OperationalError:
                    pass


_MIGRATIONS = [
    {
        "version": 1,
        "description": "Обновление дефолтов traffic_collect_interval, traffic_history_hours",
        "sql": [
            "UPDATE settings SET value='2' WHERE key='traffic_collect_interval'",
            "UPDATE settings SET value='0.5' WHERE key='traffic_history_hours'",
        ],
    },
    {
        "version": 2,
        "description": "allowed_countries → blocked_countries (смена allowlist на blocklist)",
        "sql": [],
    },
]


def _run_migrations(c: sqlite3.Cursor) -> None:
    """Применяет миграции по version."""
    current = 0
    row = c.execute("SELECT value FROM settings WHERE key='schema_version'").fetchone()
    if row:
        current = int(row["value"])
    for m in _MIGRATIONS:
        if m["version"] > current:
            for sql in m.get("sql", []):
                c.execute(sql)

            if m["version"] == 2:
                _migrate_allowed_to_blocked(c)

            c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('schema_version', ?)",
                      (str(m["version"]),))
            from .utils import add_log
            add_log("INFO", f"Migration v{m['version']}: {m['description']}")


def _migrate_allowed_to_blocked(c: sqlite3.Cursor) -> None:
    """allowed_countries (allowlist) → blocked_countries (blocklist), v2."""
    from .utils import add_log

    row = c.execute("SELECT value FROM settings WHERE key='allowed_countries'").fetchone()
    old_val = row["value"].strip() if row else ""
    if old_val:
        add_log(
            "WARN",
            f"Migration v2: old 'allowed_countries' had value '{old_val[:80]}...'. "
            "Система фильтрации изменена с allowlist на blocklist. "
            "Старое значение удалено. Настройте блокировку стран заново в Settings → Country Filter.",
        )
    c.execute("DELETE FROM settings WHERE key='allowed_countries'")


def init_db() -> None:
    """Создаёт/дополняет таблицы и устанавливает настройки по умолчанию."""
    conn = _get_conn()
    c = conn.cursor()
    _ensure_schema(conn)

    c.execute("CREATE INDEX IF NOT EXISTS idx_proxies_status ON proxies(status)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_proxies_speed_kbps ON proxies(speed_kbps)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_proxies_latency ON proxies(latency)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_proxies_source_id ON proxies(source_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_proxies_failed_since ON proxies(failed_since)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_traffic_history_collected_at ON traffic_history(collected_at)")

    # backfill security для старых строк
    from .vless import parse_vless

    c.execute("SELECT id, link FROM proxies WHERE security IS NULL OR security = ''")
    for row in c.fetchall():
        parsed = parse_vless(row["link"])
        if parsed:
            sec = parsed.get("security", "none") or "none"
            c.execute("UPDATE proxies SET security=? WHERE id=?", (sec, row["id"]))
        else:
            c.execute("UPDATE proxies SET security='none' WHERE id=?", (row["id"],))

    _run_migrations(c)

    defaults = {
        "xray_bin": "/usr/local/bin/xray",
        "xray_config_path": str(default_xray_config_path()),
        "proxy_listen": "0.0.0.0",
        "max_active_proxies": "30",
        "safe_only_import": "false",
        "blocked_countries": "",
        "probe_url": "https://www.gstatic.com/generate_204",
        # Интервалы и тюнинг
        "check_interval_db": "1800",
        "check_interval_import": "10800",
        "vless_per_proxy_timeout": "3",
        "log_trim_every": "500",
        "log_keep": "2000",
        "geosite_rules": "[]",
        "geo_enabled": "true",
        "observatory_probe_interval": "10s",
        "speed_test_enabled": "true",
        "speed_test_max": "15",
        "speed_test_url": "http://speedtest.selectel.ru/10MB",
        "apply_after_test": "true",
        "balancer_strategy": "random",
        "handshake_timeout": "5",
        "conn_idle": "300",
        "min_speed_mbps": "0",
        "speed_test_adaptive_sec": "2",
        "sniffing_enabled": "true",
        "sniffing_dest_override": "http,tls",
        "sniffing_route_only": "true",
        # Performance tuning
        "max_workers": "15",
        "probe_timeout": "3",
        "xray_startup_retries": "15",
        # Traffic monitoring
        "traffic_collect_interval": "2",
        "traffic_history_hours": "0.5",
        "db_check_auto_cleanup": "false",
    }
    for k, v in defaults.items():
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))

    conn.commit()
    conn.close()

    # Стартовая чистка логов по настройкам
    from .utils import trim_logs_startup

    trim_logs_startup()


class Settings:
    """Работа с настройками из таблицы settings в БД."""

    @staticmethod
    def get(key: str, default: str = "") -> str:
        """Возвращает значение настройки из БД."""
        rows = db_q("SELECT value FROM settings WHERE key=?", (key,))
        return rows[0]["value"] if rows else default

    @staticmethod
    def set(key: str, value: str) -> None:
        """Сохраняет значение настройки в БД."""
        db_q("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))

    @classmethod
    def xray_bin(cls) -> str:
        """Путь к бинарнику Xray из настроек."""
        return cls.get("xray_bin", "xray")

    @classmethod
    def proxy_listen(cls) -> str:
        """Адрес для SOCKS/HTTP inbounds (0.0.0.0 для LAN)."""
        return cls.get("proxy_listen", "0.0.0.0")

    @classmethod
    def max_active_proxies(cls) -> int:
        """Максимальное количество активных прокси в конфиге."""
        return int(cls.get("max_active_proxies", "30"))

    @classmethod
    def safe_only_import(cls) -> bool:
        """True если импортировать только прокси с шифрованием (reality/tls)."""
        return cls.get("safe_only_import", "false") == "true"

    @classmethod
    def blocked_countries(cls) -> str:
        """Список заблокированных стран (строка с кодами через запятую).
        Пустая строка — не блокировать никого (все страны разрешены)."""
        return cls.get("blocked_countries", "").strip()

    @classmethod
    def probe_url(cls) -> str:
        """URL для проверки работоспособности прокси (observatory)."""
        return cls.get("probe_url", "https://www.gstatic.com/generate_204")

    @classmethod
    def check_interval_db(cls) -> int:
        """Интервал проверки прокси из БД, секунд."""
        return int(cls.get("check_interval_db", "1800"))

    @classmethod
    def check_interval_import(cls) -> int:
        """Интервал импорт + проверка, секунд."""
        return int(cls.get("check_interval_import", "10800"))

    @classmethod
    def vless_per_proxy_timeout(cls) -> int:
        """Таймаут VLESS-теста одного прокси, секунд."""
        return int(cls.get("vless_per_proxy_timeout", "5"))

    @classmethod
    def log_trim_every(cls) -> int:
        """Чистить логи каждые N записей."""
        return int(cls.get("log_trim_every", "500"))

    @classmethod
    def log_keep(cls) -> int:
        """Оставлять последние N записей после чистки."""
        return int(cls.get("log_keep", "2000"))

    @classmethod
    def geosite_rules(cls) -> list[dict]:
        """Список geosite-правил для routing Xray (JSON-строка)."""
        import json

        raw = cls.get("geosite_rules", "[]")
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return []

    @classmethod
    def min_speed_kbps(cls) -> int:
        """Минимальная скорость профиля в kbps. 0 = фильтр отключён."""
        raw = cls.get("min_speed_mbps", "0")
        try:
            mbps = float(raw)
            return int(mbps * 1000) if mbps > 0 else 0
        except (ValueError, TypeError):
            return 0

    @classmethod
    def speed_test_adaptive_sec(cls) -> int:
        """Через сколько секунд adaptive speed test проверяет порог."""
        return max(1, int(cls.get("speed_test_adaptive_sec", "2")))

    @classmethod
    def max_workers(cls) -> int:
        """Количество параллельных воркеров для тестирования прокси."""
        return max(1, min(30, int(cls.get("max_workers", "10"))))

    @classmethod
    def probe_timeout(cls) -> int:
        """Таймаут проверки прокси (секунды)."""
        return max(1, min(15, int(cls.get("probe_timeout", "5"))))

    @classmethod
    def xray_startup_retries(cls) -> int:
        """Количество попыток дождаться старта Xray (каждая 0.1с)."""
        return max(5, min(50, int(cls.get("xray_startup_retries", "30"))))

    @classmethod
    def traffic_collect_interval(cls) -> int:
        """Интервал сбора статистики трафика, секунд."""
        return max(2, int(cls.get("traffic_collect_interval", "2")))

    @classmethod
    def traffic_history_hours(cls) -> float:
        """Сколько часов хранить историю трафика."""
        return max(0.5, float(cls.get("traffic_history_hours", "0.5")))

def default_xray_config_path() -> Path:
    """Определяет путь к конфигу Xray по умолчанию."""
    if ETC_XRAY_CONFIG.exists():
        return ETC_XRAY_CONFIG
    return DEFAULT_XRAY_CONFIG


def xray_config_path() -> Path:
    """Определяет актуальный путь к конфигу Xray с учётом настроек и автоисправления."""
    default_path = default_xray_config_path()
    configured = Settings.get("xray_config_path", "")
    if not configured:
        return default_path
    p = Path(configured)
    try:
        if p.exists():
            return p
    except Exception:
        pass
    if default_path.exists() and str(default_path) != configured:
        try:
            Settings.set("xray_config_path", str(default_path))
        except Exception:
            pass
    return default_path
