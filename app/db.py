"""Работа с SQLite: инициализация схемы, запросы, настройки."""

import sqlite3
from pathlib import Path

from config import DATABASE, ETC_XRAY_CONFIG, DEFAULT_XRAY_CONFIG


def _get_conn():
    """Создаёт и возвращает новое подключение к БД."""
    conn = sqlite3.connect(str(DATABASE), timeout=15)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.row_factory = sqlite3.Row
    return conn


def db_q(sql, params=()):
    """Выполняет SQL-запрос с параметрами, коммитит и возвращает результаты."""
    conn = _get_conn()
    try:
        c = conn.cursor()
        c.execute(sql, params)
        conn.commit()
        return c.fetchall()
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
        ("status", "TEXT DEFAULT 'pending'"),
        ("latency", "INTEGER DEFAULT 0"),
        ("added_at", "TIMESTAMP"),
        ("failed_since", "TIMESTAMP"),
        ("security", "TEXT DEFAULT ''"),
        ("latency_vless", "INTEGER DEFAULT 0"),
        ("source_id", "INTEGER"),
    ],
    "sources": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("name", "TEXT"),
        ("url", "TEXT UNIQUE"),
        ("last_import", "TIMESTAMP"),
        ("created_at", "TIMESTAMP"),
    ],
    "logs": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("timestamp", "TIMESTAMP"),
        ("level", "TEXT"),
        ("message", "TEXT"),
    ],
    "settings": [
        ("key", "TEXT PRIMARY KEY"),
        ("value", "TEXT"),
    ],
}


def _ensure_schema(conn):
    """Проверяет эталонную схему и добавляет недостающие таблицы/колонки."""
    c = conn.cursor()
    for table, columns in _SCHEMA.items():
        # Собираем полный CREATE TABLE со всеми колонками
        cols_sql = ", ".join(f"{name} {typ}" for name, typ in columns)
        c.execute(f"CREATE TABLE IF NOT EXISTS {table} ({cols_sql})")
        # Какие колонки уже есть в существующей таблице
        existing = {
            row[1] for row in c.execute(f"PRAGMA table_info({table})").fetchall()
        }
        for col_name, col_type in columns:
            if col_name not in existing:
                try:
                    c.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}")
                except sqlite3.OperationalError:
                    pass


def init_db():
    """Создаёт/дополняет таблицы и устанавливает настройки по умолчанию."""
    conn = _get_conn()
    c = conn.cursor()
    _ensure_schema(conn)

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

    defaults = {
        "xray_bin": "/usr/local/bin/xray",
        "xray_config_path": str(default_xray_config_path()),
        "proxy_listen": "0.0.0.0",
        "max_active_proxies": "30",
        "safe_only_import": "false",
        "allowed_countries": "",
        "probe_url": "https://www.gstatic.com/generate_204",
        # Интервалы и тюнинг
        "check_interval": "600",
        "vless_interval": "10800",
        "vless_per_proxy_timeout": "5",
        "log_trim_every": "500",
        "log_keep": "2000",
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
    def get(key, default=""):
        """Возвращает значение настройки из БД."""
        rows = db_q("SELECT value FROM settings WHERE key=?", (key,))
        return rows[0]["value"] if rows else default

    @staticmethod
    def set(key, value):
        """Сохраняет значение настройки в БД."""
        db_q("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))

    @classmethod
    def xray_bin(cls):
        """Путь к бинарнику Xray из настроек."""
        return cls.get("xray_bin", "xray")

    @classmethod
    def proxy_listen(cls):
        """Адрес для SOCKS/HTTP inbounds (0.0.0.0 для LAN)."""
        return cls.get("proxy_listen", "0.0.0.0")

    @classmethod
    def max_active_proxies(cls):
        """Максимальное количество активных прокси в конфиге."""
        return int(cls.get("max_active_proxies", "30"))

    @classmethod
    def safe_only_import(cls):
        """True если импортировать только прокси с шифрованием (reality/tls)."""
        return cls.get("safe_only_import", "false") == "true"

    @classmethod
    def allowed_countries(cls):
        """Список разрешённых стран (строка с кодами через запятую)."""
        return cls.get("allowed_countries", "").strip()

    @classmethod
    def probe_url(cls):
        """URL для проверки работоспособности прокси (observatory)."""
        return cls.get("probe_url", "https://www.gstatic.com/generate_204")

    @classmethod
    def check_interval(cls):
        """Пауза между циклами фонового чекера, секунд (по умолчанию 600 = 10 мин)."""
        return int(cls.get("check_interval", "600"))

    @classmethod
    def vless_interval(cls):
        """Как часто запускать VLESS-тест + reimport, секунд (по умолчанию 10800 = 3 часа)."""
        return int(cls.get("vless_interval", "10800"))

    @classmethod
    def vless_per_proxy_timeout(cls):
        """Таймаут VLESS-теста одного прокси, секунд (по умолчанию 5)."""
        return int(cls.get("vless_per_proxy_timeout", "5"))

    @classmethod
    def log_trim_every(cls):
        """Чистить логи каждые N записей."""
        return int(cls.get("log_trim_every", "500"))

    @classmethod
    def log_keep(cls):
        """Оставлять последние N записей после чистки."""
        return int(cls.get("log_keep", "2000"))


def default_xray_config_path():
    """Определяет путь к конфигу Xray по умолчанию."""
    if ETC_XRAY_CONFIG.exists():
        return ETC_XRAY_CONFIG
    return DEFAULT_XRAY_CONFIG


def xray_config_path():
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
