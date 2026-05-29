"""Тестирование VLESS прокси: проверка доступности, обновление статуса."""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .db import db_q
from .utils import add_log, now_utc, enrich_country
from .vless import parse_vless
from .xray_config import apply_all_proxies
from config import TEST_WORKERS


def check_proxy_via_curl(host, port, timeout=5):
    """Проверяет доступность хоста:порта через TCP-соединение."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def test_proxy(link):
    """Тестирует один прокси: возвращает (ok: bool, latency_ms: int)."""
    parsed = parse_vless(link)
    if not parsed:
        return False, 0
    start = time.time()
    ok = check_proxy_via_curl(parsed["host"], parsed["port"])
    latency = int((time.time() - start) * 1000) if ok else 0
    return ok, latency


def update_proxy_status(pid, ok, lat):
    """Обновляет статус, latency, last_checked и failed_since в БД."""
    now = now_utc()
    if ok:
        db_q(
            "UPDATE proxies SET status='working', latency=?, last_checked=?, failed_since=NULL WHERE id=?",
            (lat, now, pid),
        )
    else:
        db_q(
            "UPDATE proxies SET status='failed', latency=?, last_checked=?, failed_since=COALESCE(failed_since, ?) WHERE id=?",
            (lat, now, now, pid),
        )


def _check_one(row):
    """Проверяет один прокси (для параллельного запуска). Возвращает (id, host, country, ok)."""
    ok, lat = test_proxy(row["link"])
    update_proxy_status(row["id"], ok, lat)
    return row["id"], row["host"], row["country"], ok


def test_and_update(link):
    """Тестирует прокси по ссылке и при успехе применяет конфиг."""
    row = db_q("SELECT id FROM proxies WHERE link=?", (link,))
    if not row:
        return
    ok, lat = test_proxy(link)
    update_proxy_status(row[0]["id"], ok, lat)
    add_log("INFO", f"Tested {link[:50]} → {'working' if ok else 'failed'} ({lat}ms)")
    if ok:
        apply_all_proxies()


def update_all():
    """Тестирует все прокси из БД параллельно и применяет конфиг."""
    rows = db_q("SELECT id, link, host, country FROM proxies")
    if not rows:
        add_log("WARN", "Test all: no proxies to test")
        return
    ok_count = 0
    fail_count = 0
    with ThreadPoolExecutor(max_workers=TEST_WORKERS) as pool:
        futures = {pool.submit(_check_one, dict(r)): r for r in rows}
        for fut in as_completed(futures):
            try:
                pid, host, country, ok = fut.result()
                if ok:
                    ok_count += 1
                else:
                    fail_count += 1
                if not country:
                    enrich_country(pid, host)
            except Exception:
                pass
    apply_all_proxies()
    add_log("INFO", f"Test all completed: {ok_count} working, {fail_count} failed ({len(rows)} total)")
