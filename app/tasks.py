"""Фоновые задачи: автотестирование, автоимпорт, обновление подписки."""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .db import db_q
from .utils import add_log, now_utc, enrich_all_unknown_countries
from .importer import import_from_url
from .xray_config import apply_all_proxies, _update_subscribe_cache
from config import CHECK_INTERVAL, REIMPORT_CYCLES, TEST_WORKERS


def _check_one(row):
    """Проверяет один прокси (для параллельного запуска в фоне)."""
    from .tester import test_proxy, update_proxy_status

    ok, lat = test_proxy(row["link"])
    update_proxy_status(row["id"], ok, lat)
    return row["id"], row["host"], row["country"], ok


def reimport_all_sources():
    """Импортирует прокси из всех источников."""
    rows = db_q("SELECT id, url FROM sources")
    total = 0
    for r in rows:
        added = import_from_url(r["url"])
        db_q("UPDATE sources SET last_import=? WHERE id=?", (now_utc(), r["id"]))
        total += added
    if total:
        add_log("INFO", f"Hourly re-import: {total} new proxies")


def background_checker():
    """Главный фоновый цикл: тестирует каждые 60с, переимпортирует каждый час."""
    cycle = 0
    while True:
        time.sleep(CHECK_INTERVAL)
        cycle += 1

        rows = db_q("SELECT id, link, host, country FROM proxies")
        if not rows:
            if cycle % REIMPORT_CYCLES == 0:
                reimport_all_sources()
            continue

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
                except Exception:
                    pass
        enrich_all_unknown_countries()
        apply_all_proxies()
        add_log("INFO", f"BG check: {ok_count} working, {fail_count} failed ({len(rows)} total)")

        if cycle % 60 == 0:
            reimport_all_sources()
            _update_subscribe_cache()
            add_log("INFO", "Subscribe cache updated after hourly reimport")
