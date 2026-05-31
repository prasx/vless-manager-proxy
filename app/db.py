"""Работа с SQLite: инициализация схемы, запросы, настройки."""

import sqlite3
from pathlib import Path

from config import BASE_DIR, DATABASE, ETC_XRAY_CONFIG, DEFAULT_XRAY_CONFIG


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


def init_db():
    """Создаёт таблицы и дефолтные настройки при первом запуске."""
    conn = _get_conn()
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS proxies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            link TEXT UNIQUE,
            host TEXT,
            port INTEGER,
            country TEXT,
            status TEXT DEFAULT 'pending',
            latency INTEGER DEFAULT 0,
            last_checked TIMESTAMP,
            added_at TIMESTAMP,
            failed_since TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            url TEXT UNIQUE,
            last_import TIMESTAMP,
            created_at TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP,
            level TEXT,
            message TEXT
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
    """)
    try:
        c.execute("ALTER TABLE proxies ADD COLUMN failed_since TIMESTAMP")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE proxies ADD COLUMN security TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE proxies ADD COLUMN latency_vless INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass

    # backfill security for existing rows
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
    }
    for k, v in defaults.items():
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))
    conn.commit()
    conn.close()


def get_setting(key, default=""):
    """Возвращает значение настройки из БД."""
    rows = db_q("SELECT value FROM settings WHERE key=?", (key,))
    return rows[0]["value"] if rows else default


def set_setting(key, value):
    """Сохраняет значение настройки в БД."""
    db_q("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))


def xray_bin():
    """Возвращает путь к бинарнику Xray из настроек."""
    return get_setting("xray_bin", "xray")


def default_xray_config_path():
    """Определяет путь к конфигу Xray по умолчанию."""
    if ETC_XRAY_CONFIG.exists():
        return ETC_XRAY_CONFIG
    return DEFAULT_XRAY_CONFIG


def proxy_listen():
    """Адрес для SOCKS/HTTP inbounds (0.0.0.0 для LAN)."""
    return get_setting("proxy_listen", "0.0.0.0")


def xray_config_path():
    """Определяет актуальный путь к конфигу Xray с учётом настроек и автоисправления."""
    default_path = default_xray_config_path()
    configured = get_setting("xray_config_path", "")
    if not configured:
        return default_path
    p = Path(configured)
    try:
        if p.exists():
            return p
    except Exception:
        pass
    # Если в БД устаревший/неверный путь — исправляем
    if default_path.exists() and str(default_path) != configured:
        try:
            set_setting("xray_config_path", str(default_path))
        except Exception:
            pass
    return default_path
