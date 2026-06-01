"""Импорт прокси из URL-подписки."""

import sqlite3
import urllib.request

from .db import db_q, Settings, _get_conn
from .utils import add_log, now_utc
from .vless import parse_vless


def import_from_url(url, source_id=None):
    """Загружает подписку по URL, разбирает vless:// строки и сохраняет в БД.

    Учитывает флаг safe_only_import (пропускает security=none).
    Принимает source_id для привязки импортированных прокси к источнику.
    Удаляет старые прокси источника, которых больше нет в подписке.
    Возвращает количество добавленных прокси.
    """
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            content = r.read().decode("utf-8", errors="replace")
    except Exception as e:
        add_log("ERROR", f"Import failed for {url[:80]}: {e}")
        return 0
    lines = [line for line in content.splitlines() if line.startswith("vless://")]
    safe_only = Settings.safe_only_import()
    added = 0
    skipped = 0
    valid_links = []
    for link in lines:
        parsed = parse_vless(link)
        if not parsed:
            continue
        valid_links.append(link)
        sec = parsed.get("security", "none") or "none"
        if safe_only and sec == "none":
            skipped += 1
            continue
        try:
            db_q(
                "INSERT OR IGNORE INTO proxies (link,host,port,country,status,security,added_at,source_id) VALUES (?,?,?,?,?,?,?,?)",
                (
                    link,
                    parsed["host"],
                    parsed["port"],
                    parsed.get("country", ""),
                    "pending",
                    sec,
                    now_utc(),
                    source_id,
                ),
            )
            added += 1
        except sqlite3.IntegrityError:
            pass

    # Удаляем старые прокси источника, которых нет в свежей подписке
    if source_id is not None and valid_links:
        placeholders = ",".join("?" * len(valid_links))
        conn = _get_conn()
        try:
            c = conn.cursor()
            c.execute(
                f"DELETE FROM proxies WHERE source_id=? AND link NOT IN ({placeholders})",
                [source_id] + valid_links,
            )
            conn.commit()
            deleted = c.rowcount
        finally:
            conn.close()
        if deleted:
            add_log(
                "INFO", f"Cleaned up {deleted} stale proxies for source #{source_id}"
            )

    if added:
        import threading
        from .utils import enrich_all_unknown_countries

        threading.Thread(target=enrich_all_unknown_countries, daemon=True).start()
    msg = f"Imported {added} proxies"
    if skipped:
        msg += f" (skipped {skipped} unencrypted)"
    add_log("INFO", f"{msg} from {url[:60]}")
    return added
