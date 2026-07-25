"""Импорт прокси из URL-подписки и TXT-контента."""

import base64
import os
import ssl
import subprocess
import sqlite3
import time as _time
import urllib.request
from pathlib import Path

from .db import db_q, Settings, _get_conn
from .utils import add_log, now_utc
from .vless import parse_vless


def _etag_path():
    from config import DATABASE
    d = DATABASE.parent / ".import_cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _read_etag(url):
    h = str(hash(url))
    p = _etag_path() / f"etag_{h}"
    if p.exists():
        try:
            return p.read_text().strip()
        except Exception:
            pass
    return ""


def _write_etag(url, val):
    if not val:
        return
    try:
        h = str(hash(url))
        (_etag_path() / f"etag_{h}").write_text(val)
    except Exception:
        pass


def _parse_and_import_content(content, source_id=None, src_label=""):
    """Парсит контент подписки (vless:// строки, возможно в base64),
    сохраняет прокси в БД, удаляет устаревшие для указанного source_id.
    Возвращает количество добавленных прокси.
    """
    lines = [line.strip() for line in content.splitlines() if line.strip().startswith("vless://")]
    if not lines:
        try:
            decoded = base64.b64decode(content).decode("utf-8", errors="replace")
            lines = [line.strip() for line in decoded.splitlines() if line.strip().startswith("vless://")]
        except Exception:
            pass
    if not lines:
        add_log("WARN", f"No vless:// links found in content from {src_label} (content length={len(content)})")
    safe_only = Settings.safe_only_import()
    added = 0
    skipped = 0
    valid_links_set = set()
    for link in lines:
        parsed = parse_vless(link)
        if not parsed:
            continue
        if link in valid_links_set:
            continue
        valid_links_set.add(link)
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

    valid_links = list(valid_links_set)
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
    add_log("INFO", f"{msg} from {src_label}")
    return added


_IMPORT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"


def _fetch_via_curl(url, timeout=30):
    """Загружает URL через curl (обход DPI/блокировок). Возвращает bytes или бросает исключение."""
    cmd = [
        "curl", "-sS", "-L",
        "--max-time", str(timeout),
        "--connect-timeout", "10",
        "-A", _IMPORT_UA,
        "-o", "-",
        url,
    ]
    # Поддержка прокси: БД > env
    proxy = Settings.import_proxy()
    if proxy:
        cmd.extend(["--proxy", proxy])
        add_log("DEBUG", f"Using proxy for curl: {proxy[:40]}")
    r = subprocess.run(cmd, capture_output=True, timeout=timeout + 5)
    if r.returncode != 0:
        err = r.stderr.decode(errors="replace").strip()[:200]
        raise RuntimeError(f"curl failed (rc={r.returncode}): {err}")
    return r.stdout


def _build_opener():
    """Создаёт opener с поддержкой прокси и SSL."""
    handlers = []
    proxy = Settings.import_proxy()
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"https": proxy, "http": proxy}))
        add_log("DEBUG", f"Using proxy for urllib: {proxy[:40]}")
    # SSL context: разрешаем невалидные сертификаты (нужно для некоторых источников)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def import_from_url(url, source_id=None, max_retries=3):
    """Загружает подписку по URL, разбирает vless:// строки и сохраняет в БД.

    Учитывает флаг safe_only_import (пропускает security=none).
    Принимает source_id для привязки импортированных прокси к источнику.
    Удаляет старые прокси источника, которых больше нет в подписке.
    Использует ETag/If-Modified-Since для пропуска неизменённых источников.
    Повторяет при транзиентных сетевых ошибках (connection reset, timeout).
    Fallback на curl если urllib не может подключиться (DPI/блокировки).
    Возвращает количество добавленных прокси.
    Бросает RuntimeError при ошибке загрузки (сеть, HTTP).
    """
    url = url.strip().strip('"').strip("'")
    last_err = None
    opener = _build_opener()

    for attempt in range(max_retries):
        req = urllib.request.Request(url, headers={"User-Agent": _IMPORT_UA})
        etag = _read_etag(url)
        if etag:
            req.add_header("If-None-Match", etag)
        try:
            with opener.open(req, timeout=30) as r:
                raw = r.read()
                new_etag = r.headers.get("ETag") or ""
                if new_etag:
                    _write_etag(url, new_etag)
            content = raw.decode("utf-8", errors="replace")
            return _parse_and_import_content(content, source_id, url[:60])
        except urllib.error.HTTPError as e:
            if e.code == 304:
                add_log("DEBUG", f"Source unchanged (304): {url[:60]}")
                return 0
            if e.code in (429, 500, 502, 503, 504) and attempt < max_retries - 1:
                wait = 2 ** attempt
                add_log("WARN", f"HTTP {e.code} for {url[:60]}, retry {attempt+1}/{max_retries} in {wait}s")
                _time.sleep(wait)
                last_err = e
                continue
            add_log("ERROR", f"Import failed HTTP {e.code} for {url[:80]}")
            raise RuntimeError(f"HTTP {e.code}") from e
        except (urllib.error.URLError, ConnectionResetError, OSError) as e:
            if attempt < max_retries - 1:
                wait = 2 ** attempt
                add_log("WARN", f"Network error for {url[:60]}: {e}, retry {attempt+1}/{max_retries} in {wait}s")
                _time.sleep(wait)
                last_err = e
                continue
            # urllib не сработал — пробуем curl как fallback
            add_log("WARN", f"urllib failed for {url[:60]}: {e}, trying curl fallback")
            try:
                raw = _fetch_via_curl(url)
                content = raw.decode("utf-8", errors="replace")
                return _parse_and_import_content(content, source_id, url[:60])
            except Exception as curl_err:
                add_log("ERROR", f"curl fallback also failed for {url[:80]}: {curl_err}")
                raise RuntimeError(f"urllib: {e}; curl: {curl_err}") from e
        except Exception as e:
            add_log("ERROR", f"Import failed for {url[:80]}: {e}")
            raise RuntimeError(str(e)) from e

    raise RuntimeError(str(last_err))


def import_from_txt(source_id):
    """Импортирует прокси из TXT-содержимого источника.

    Читает поле content из таблицы sources, парсит vless:// строки,
    вставляет/обновляет прокси с source_id.
    Возвращает количество добавленных прокси.
    """
    rows = db_q("SELECT name, content FROM sources WHERE id=?", (source_id,))
    if not rows or not rows[0]["content"]:
        add_log("WARN", f"TXT source #{source_id} has no content")
        return 0
    name = rows[0]["name"]
    content = rows[0]["content"]
    return _parse_and_import_content(content, source_id, f"txt://{name}")
