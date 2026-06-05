"""Утилиты: работа со временем, логирование, гео-определение страны."""

import json
import threading
from datetime import datetime
from zoneinfo import ZoneInfo
from typing import Optional

from .db import _get_conn, Settings
from config import MOSCOW_TZ, UTC_TZ

_geo_cache: dict[str, str] = {}
_geo_cache_lock = threading.Lock()


def now_utc() -> datetime:
    """Наивный UTC datetime для хранения в БД (совместимость с SQLite datetime('now'))."""
    return datetime.now(UTC_TZ).replace(tzinfo=None)


def moscow_str(dt: Optional[datetime] = None) -> str:
    """Форматирование даты/времени в московском часовом поясе для отображения."""
    if dt is None:
        dt = datetime.now(MOSCOW_TZ)
    elif dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOSCOW_TZ)
    else:
        dt = dt.astimezone(MOSCOW_TZ)
    return dt.strftime("%Y-%m-%d %H:%M:%S %z")


_log_insert_count = 0
_log_count_lock = threading.Lock()


def add_log(level: str, message: str) -> None:
    """Добавляет запись в лог-таблицу БД. Автоматически подчищает старые записи."""
    global _log_insert_count
    conn = _get_conn()
    try:
        conn.execute(
            "INSERT INTO logs (timestamp, level, message) VALUES (?, ?, ?)",
            (now_utc(), level, message),
        )
        conn.commit()
    finally:
        conn.close()
    with _log_count_lock:
        _log_insert_count += 1
        do_trim = _log_insert_count % Settings.log_trim_every() == 0
    if do_trim:
        _trim_logs()


def _trim_logs() -> None:
    """Оставляет только последние N записей в логах."""
    keep = Settings.log_keep()
    conn = _get_conn()
    try:
        conn.execute(
            "DELETE FROM logs WHERE id NOT IN (SELECT id FROM logs ORDER BY id DESC LIMIT ?)",
            (keep,),
        )
        conn.commit()
    finally:
        conn.close()


def trim_logs_startup() -> None:
    """Принудительная чистка логов при старте (учитывает настройки)."""
    _trim_logs()


# ─── Определение страны ───


def detect_country(host):
    """Определяет страну по IP хоста через ip-api.com (с кешированием)."""
    with _geo_cache_lock:
        if host in _geo_cache:
            return _geo_cache[host]
    try:
        import socket
        import urllib.request

        ip = socket.gethostbyname(host)
        url = f"http://ip-api.com/json/{ip}?fields=countryCode"
        with urllib.request.urlopen(url, timeout=3) as r:
            data = json.loads(r.read().decode())
        cc = data.get("countryCode", "")
        if cc:
            with _geo_cache_lock:
                _geo_cache[host] = cc
            return cc
    except Exception:
        pass
    add_log("WARN", f"Failed to detect country for {host}")
    return ""


def enrich_country(pid, host):
    """Обновляет страну для прокси по его ID."""
    from .db import db_q

    cc = detect_country(host)
    if cc:
        db_q("UPDATE proxies SET country=? WHERE id=?", (cc, pid))
        return True
    return False


_enrich_lock = threading.Lock()

def enrich_all_unknown_countries():
    """Заполняет страну для всех прокси, у которых она отсутствует или невалидна.
    Предотвращает конкурентный запуск через threading.Lock()."""
    if not _enrich_lock.acquire(blocking=False):
        return
    try:
        from .db import db_q

        rows = db_q(
            "SELECT id, host FROM proxies WHERE country IS NULL OR country = '' OR length(country) > 2"
        )
        enriched = 0
        for r in rows:
            if enrich_country(r["id"], r["host"]):
                enriched += 1
        if enriched:
            add_log("INFO", f"Enriched country for {enriched} proxies")
    finally:
        _enrich_lock.release()
