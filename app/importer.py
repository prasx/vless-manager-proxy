"""Импорт прокси из URL-подписки."""

import sqlite3
import urllib.request

from .db import db_q, Settings
from .utils import add_log, now_utc
from .vless import parse_vless


def import_from_url(url, source_id=None):
    """Загружает подписку по URL, разбирает vless:// строки и сохраняет в БД.

    Учитывает флаг safe_only_import (пропускает security=none).
    Принимает source_id для привязки импортированных прокси к источнику.
    Возвращает количество добавленных прокси.
    """
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            content = r.read().decode("utf-8", errors="replace")
    except Exception as e:
        add_log("ERROR", f"Import failed for {url[:80]}: {e}")
        return 0
    links = [line for line in content.splitlines() if line.startswith("vless://")]
    safe_only = Settings.safe_only_import()
    added = 0
    skipped = 0
    for link in links:
        parsed = parse_vless(link)
        if not parsed:
            continue
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
    msg = f"Imported {added} proxies"
    if skipped:
        msg += f" (skipped {skipped} unencrypted)"
    add_log("INFO", f"{msg} from {url[:60]}")
    return added
