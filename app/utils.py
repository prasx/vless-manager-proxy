"""Утилиты: работа со временем, логирование, константы, диагностика Xray."""

import json
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from .db import _get_conn, proxy_listen
from config import (BASE_DIR, SUBSCRIBE_FILE, MOSCOW_TZ, UTC_TZ,
                     LOG_TRIM_EVERY, LOG_KEEP)

_geo_cache = {}
_geo_cache_lock = threading.Lock()


def now_utc():
    """Наивный UTC datetime для хранения в БД (совместимость с SQLite datetime('now'))."""
    return datetime.now(UTC_TZ).replace(tzinfo=None)


def moscow_str(dt=None):
    """Форматирование даты/времени в московском часовом поясе для отображения."""
    if dt is None:
        dt = datetime.now(MOSCOW_TZ)
    elif dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOSCOW_TZ)
    else:
        dt = dt.astimezone(MOSCOW_TZ)
    return dt.strftime("%Y-%m-%d %H:%M:%S %z")


_LOG_TRIM_EVERY = LOG_TRIM_EVERY
_log_insert_count = 0
_log_count_lock = threading.Lock()


def add_log(level, message):
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
        do_trim = _log_insert_count % _LOG_TRIM_EVERY == 0
    if do_trim:
        _trim_logs()


def _trim_logs(keep=LOG_KEEP):
    """Оставляет только last N записей в логах."""
    conn = _get_conn()
    try:
        conn.execute(
            "DELETE FROM logs WHERE id NOT IN (SELECT id FROM logs ORDER BY id DESC LIMIT ?)",
            (keep,),
        )
        conn.commit()
    finally:
        conn.close()


# ─── Диагностика Xray ───


def detect_systemd_xray_config():
    """Извлекает путь к конфигу Xray из systemd unit (ExecStart)."""
    try:
        r = subprocess.run(
            ["systemctl", "show", "xray", "-p", "ExecStart", "--value"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if r.returncode != 0:
            return None
        text = r.stdout.strip()
        for flag in ("-config", "-c"):
            if flag not in text:
                continue
            parts = text.replace("=", " ").split()
            for i, p in enumerate(parts):
                if p == flag and i + 1 < len(parts):
                    return parts[i + 1]
    except Exception:
        pass
    return None


def systemd_xray_active():
    """Проверяет, активен ли systemd-сервис xray."""
    try:
        r = subprocess.run(
            ["systemctl", "is-active", "xray"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        return r.stdout.strip() == "active"
    except Exception:
        return False


def _ss_listen(port):
    """Проверяет, слушает ли процесс указанный TCP-порт (через ss)."""
    try:
        r = subprocess.run(["ss", "-lntp"], capture_output=True, text=True, timeout=3)
        for line in (r.stdout or "").splitlines():
            if f":{port}" in line:
                return line.strip()
    except Exception:
        pass
    return None


def _config_inbound_listeners(path=None):
    """Читает входящие соединения (socks/http) из JSON-конфига."""
    from .db import xray_config_path

    p = Path(path) if path else xray_config_path()
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text())
        return [
            {
                "protocol": ib.get("protocol"),
                "port": ib.get("port"),
                "listen": ib.get("listen"),
            }
            for ib in data.get("inbounds", [])
            if ib.get("protocol") in ("socks", "http")
        ]
    except Exception:
        return []


def xray_diagnose():
    """Собирает диагностическую информацию о состоянии Xray."""
    from .db import xray_config_path

    mgr = str(xray_config_path().resolve())
    systemd_cfg = detect_systemd_xray_config()
    inbounds = _config_inbound_listeners()
    has_socks = any(
        ib.get("port") == 1080 and ib.get("protocol") == "socks" for ib in inbounds
    )
    return {
        "manager_config_path": mgr,
        "systemd_config_path": systemd_cfg,
        "config_mismatch": bool(systemd_cfg and systemd_cfg != mgr),
        "systemd_active": systemd_xray_active(),
        "config_inbounds": inbounds,
        "socks_in_config": has_socks,
        "ports": {str(p): _ss_listen(p) for p in (1080, 1081, 10085)},
        "proxy_listen": proxy_listen(),
    }


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
    return ""


def enrich_country(pid, host):
    """Обновляет страну для прокси по его ID."""
    from .db import db_q

    cc = detect_country(host)
    if cc:
        db_q("UPDATE proxies SET country=? WHERE id=?", (cc, pid))
        return True
    return False


def enrich_all_unknown_countries():
    """Заполняет страну для всех прокси, у которых она отсутствует или невалидна."""
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
