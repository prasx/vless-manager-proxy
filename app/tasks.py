"""Фоновые задачи: TCP всех параллельно + VLESS пачками, переимпорт."""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .db import db_q
from .utils import add_log, now_utc, enrich_country, enrich_all_unknown_countries
from .importer import import_from_url
from .tester import (
    test_proxy,
    update_proxy_status,
    test_vless_real,
    update_vless_status,
)
from .xray_config import apply_all_proxies
from config import (
    CHECK_INTERVAL,
    REIMPORT_CYCLES,
    TEST_WORKERS,
    VLESS_BATCH_SIZE,
    VLESS_PER_PROXY_TIMEOUT,
)

_vless_busy = False


def _tcp_check_one(row):
    ok, lat = test_proxy(row["link"])
    update_proxy_status(row["id"], ok, lat)
    return row["id"], row["host"], row["country"], ok


def reimport_all_sources():
    rows = db_q("SELECT id, url FROM sources")
    total = 0
    for r in rows:
        added = import_from_url(r["url"])
        db_q("UPDATE sources SET last_import=? WHERE id=?", (now_utc(), r["id"]))
        total += added
    if total:
        add_log("INFO", f"Hourly re-import: {total} new proxies")


def background_checker():
    global _vless_busy
    cycle = 0
    while True:
        time.sleep(CHECK_INTERVAL)
        cycle += 1

        rows = db_q("SELECT id, link, host, country FROM proxies")
        if not rows:
            if cycle % REIMPORT_CYCLES == 0:
                reimport_all_sources()
            continue

        # ─── TCP всех прокси параллельно ───
        tcp_ok = 0
        with ThreadPoolExecutor(max_workers=TEST_WORKERS) as pool:
            futures = {pool.submit(_tcp_check_one, dict(r)): r for r in rows}
            for fut in as_completed(futures):
                try:
                    pid, host, country, ok = fut.result()
                    if ok:
                        tcp_ok += 1
                    if not country:
                        enrich_country(pid, host)
                except Exception:
                    pass
        add_log("INFO", f"BG TCP: {tcp_ok}/{len(rows)} working")

        # ─── VLESS пачка (не чаще одного одновременного запуска) ───
        if not _vless_busy:
            vless_rows = db_q(
                "SELECT id, link FROM proxies WHERE status='working' ORDER BY latency_vless ASC, last_checked ASC NULLS FIRST LIMIT ?",
                (VLESS_BATCH_SIZE,),
            )
            if vless_rows:
                _vless_busy = True
                vless_ok = 0
                for r in vless_rows:
                    ok, lat = test_vless_real(
                        r["link"], timeout=VLESS_PER_PROXY_TIMEOUT
                    )
                    update_vless_status(r["id"], ok, lat if ok else 0)
                    if ok:
                        vless_ok += 1
                _vless_busy = False
                add_log(
                    "INFO",
                    f"BG VLESS: {vless_ok}/{len(vless_rows)} ok (batch {VLESS_BATCH_SIZE})",
                )

        enrich_all_unknown_countries()
        apply_all_proxies()

        if cycle % REIMPORT_CYCLES == 0:
            reimport_all_sources()
            add_log("INFO", "Hourly reimport completed")
