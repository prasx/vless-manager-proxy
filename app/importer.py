"""Импорт прокси из URL-подписок и TXT-контента.

Подход: один источник — один структурированный результат (статус, причина,
счётчики). Сбой источника не прерывает остальные, а оркестратор
`import_sources()` ограничивает прогон бюджетом времени и срабатывает
предохранителем, когда сеть недоступна целиком.

Зачем предохранитель: раньше каждый источник проходил 3 попытки urllib плюс
curl-фолбэк со своими таймаутами. При недоступной сети (типичный случай:
GitHub/GitLab закрыты без прокси) прогон из десятка источников молотил один и
тот же таймаут минутами, всё это время удерживая эксклюзивную блокировку
замеров, а в UI это выглядело как «импорт всегда с ошибкой».
"""

import base64
import hashlib
import http.client
import json
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from .db import _get_conn, db_q, Settings
from .utils import add_log, now_utc
from .vless import parse_vless

# ─── Статусы результата импорта одного источника ───
STATUS_OK = "ok"
STATUS_NOT_MODIFIED = "not_modified"
STATUS_EMPTY = "empty"            # скачали, но vless:// ссылок нет
STATUS_NO_CONTENT = "no_content"  # TXT-источник пуст
STATUS_HTTP_ERROR = "http_error"
STATUS_NETWORK_ERROR = "network_error"
STATUS_BAD_URL = "bad_url"
STATUS_SKIPPED = "skipped"        # пропущен предохранителем или бюджетом
STATUS_ERROR = "error"

# Статусы, при которых источник реально ответил (можно обновлять last_import)
REACHED_STATUSES = {STATUS_OK, STATUS_EMPTY, STATUS_NOT_MODIFIED}
# Статусы, при которых сеть до источника не дошла
OFFLINE_STATUSES = {STATUS_NETWORK_ERROR}

STATUS_LABELS = {
    STATUS_OK: "ок",
    STATUS_NOT_MODIFIED: "без изменений",
    STATUS_EMPTY: "нет vless-ссылок",
    STATUS_NO_CONTENT: "пустой TXT",
    STATUS_HTTP_ERROR: "ошибка HTTP",
    STATUS_NETWORK_ERROR: "сеть недоступна",
    STATUS_BAD_URL: "некорректный URL",
    STATUS_SKIPPED: "пропущен",
    STATUS_ERROR: "ошибка",
}

IMPORT_TIMEOUT = 20       # таймаут сокетной операции urllib, сек (не общее время скачивания)
CURL_TIMEOUT = 12         # таймаут curl-фолбэка, сек
IMPORT_BUDGET_SEC = 90    # бюджет времени на прогон всех источников, сек
NETWORK_BREAK_AFTER = 2   # столько сетевых сбоев подряд — сеть считаем лежащей

# Запись в БД и чистка устаревших сериализуются: два одновременных импорта
# (ручной «Импорт всех» и стадия конвейера) иначе удаляли бы свежие строки
# друг друга, потому что у каждого свой снимок ссылок источника.
_STORE_LOCK = threading.Lock()
# Обогащение стран — один прогон за раз, чтобы импорт десятка источников
# не поднимал десяток одинаковых потоков.
_ENRICH_LOCK = threading.Lock()


def status_label(status: str) -> str:
    """Человекочитаемая подпись статуса (для логов и UI)."""
    return STATUS_LABELS.get(status, status or "—")


def _result(source_id, name, src_type, status, **kw) -> dict:
    """Структурированный результат импорта одного источника."""
    result = {
        "id": source_id,
        "name": name or "",
        "type": src_type or "url",
        "status": status,
        "status_label": status_label(status),
        "reason": "",
        "added": 0,          # реально вставлено новых прокси
        "duplicates": 0,     # ссылки, которые уже были в БД
        "skipped_unencrypted": 0,
        "parsed": 0,         # сколько vless:// ссылок разобрано
        "deleted": 0,        # удалено устаревших прокси источника
        "http_status": None,
        "seconds": 0.0,
        "error": "",         # заполняется, когда статус — не успех
    }
    result.update(kw)
    return result


def _fail(result: dict, message: str) -> dict:
    """Помечает результат как неуспешный: статус остаётся, добавляется причина."""
    result["reason"] = message
    result["error"] = message
    return _finish(result)


def _finish(result: dict) -> dict:
    """Единая нормализация перед возвратом результата.

    Подпись статуса и поле error выводятся из итогового статуса: без этого
    результат со статусом network_error уезжал в UI с подписью «ок»,
    потому что подпись вычислялась при создании словаря.
    """
    result["status_label"] = status_label(result["status"])
    if result["status"] not in (STATUS_OK, STATUS_NOT_MODIFIED) and not result.get("error"):
        result["error"] = result.get("reason") or result["status_label"]
    return result


# ─── ETag-кеш ───


def _etag_path() -> Path:
    """Каталог кеша ETag рядом с БД. Недоступный каталог — не ошибка импорта."""
    from config import DATABASE

    d = Path(DATABASE).parent / ".import_cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _etag_file(url: str) -> Path:
    # Имя файла — стабильный sha1 от URL. Прежний str(hash(url)) зависел от
    # рандомизации хешей в Python: после каждого перезапуска процесса кеш
    # промахивался, и источники скачивались заново.
    key = hashlib.sha1(url.encode("utf-8")).hexdigest()[:16]
    return _etag_path() / f"etag_{key}.json"


def _read_cache(url: str) -> dict:
    """Сохранённые заголовки кеша (ETag, Last-Modified). Пустой словарь при сбое."""
    try:
        path = _etag_file(url)
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _write_cache(url: str, etag: str, last_modified: str) -> None:
    if not etag and not last_modified:
        return
    try:
        _etag_file(url).write_text(
            json.dumps({"etag": etag or "", "last_modified": last_modified or ""}),
            encoding="utf-8",
        )
    except Exception:
        pass


# ─── Загрузка ───


class FetchError(Exception):
    """Сбой загрузки с классификацией: сеть, HTTP или некорректный URL."""

    def __init__(self, kind: str, message: str, http_status: int | None = None):
        self.kind = kind
        self.message = message
        self.http_status = http_status
        super().__init__(message)


class NotModified(Exception):
    """Источник не изменился (HTTP 304)."""


def _classify(exc: Exception) -> tuple[str, str]:
    """Превращает исключение загрузки в (вид, человекочитаемая причина)."""
    reason = getattr(exc, "reason", None) or exc
    if isinstance(exc, urllib.error.HTTPError):
        return "http", f"HTTP {exc.code}"
    # Обрыв загрузки: сервер обещал больше байт, чем отдал. Это сетевой сбой,
    # и распознать его важно: усечённая подписка выглядит как «источник
    # сократился», а чистка устаревших удалила бы рабочие профили.
    if isinstance(reason, http.client.IncompleteRead):
        got = len(reason.partial or b"")
        return "network", f"загрузка неполная: получено {got} из {reason.expected} байт"
    if isinstance(reason, socket.gaierror):
        return "network", f"DNS не разрешается: {reason}"
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return "network", "таймаут соединения"
    if isinstance(reason, ssl.SSLError):
        return "network", f"TLS: {getattr(reason, 'reason', reason)}"
    if isinstance(reason, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return "network", "соединение сброшено"
    if isinstance(reason, ValueError):
        return "bad_url", f"некорректный URL: {reason}"
    if isinstance(reason, OSError):
        return "network", f"{type(reason).__name__}: {reason}"
    return "error", str(reason)


def _build_opener():
    """opener с поддержкой прокси из настроек и без проверки сертификатов.

    Сертификаты не проверяем осознанно: часть публичных подписок отдаётся с
    самоподписанными или просроченными сертификатами, а подписка — это не
    доверенный канал, а список ссылок.
    """
    handlers = []
    proxy = Settings.import_proxy()
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"https": proxy, "http": proxy}))
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


_IMPORT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)


def _fetch_urllib(url: str, *, use_etag: bool, timeout: int) -> tuple[bytes, dict]:
    """Одна попытка загрузки через urllib.

    Бросает NotModified при 304 и FetchError при остальных сбоях.
    Конструирование Request внутри try: некорректный URL (например,
    `txt://имя` у источника типа url) обязан стать статусом bad_url,
    а не «ошибкой вообще».
    """
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _IMPORT_UA})
        cache = _read_cache(url) if use_etag else {}
        if cache.get("etag"):
            req.add_header("If-None-Match", cache["etag"])
        if cache.get("last_modified"):
            req.add_header("If-Modified-Since", cache["last_modified"])

        opener = _build_opener()
        with opener.open(req, timeout=timeout) as r:
            raw = r.read()
            meta = {
                "etag": r.headers.get("ETag") or "",
                "last_modified": r.headers.get("Last-Modified") or "",
                "content_length": r.headers.get("Content-Length") or "",
                "content_type": r.headers.get("Content-Type") or "",
                "http_status": getattr(r, "status", 200),
            }
    except urllib.error.HTTPError as e:
        if e.code == 304:
            raise NotModified() from e
        raise FetchError("http", f"HTTP {e.code}", http_status=e.code) from e
    except Exception as e:
        # Сюда попадают и ошибки разбора URL (ValueError), и обрывы загрузки
        # (http.client.IncompleteRead): и то и другое обязано стать понятным
        # статусом, а не «ошибкой вообще».
        kind, message = _classify(e)
        raise FetchError(kind, message) from e

    # Частичная загрузка опаснее пустой: усечённый список выглядит как «источник
    # сократился», и чистка устаревших прокси удалила бы рабочие профили.
    expected = str(meta.get("content_length") or "").strip()
    if expected.isdigit() and int(expected) > 0 and len(raw) != int(expected):
        raise FetchError(
            "network",
            f"загрузка неполная: получено {len(raw)} из {expected} байт",
        )
    return raw, meta


def _fetch_curl(url: str, timeout: int = CURL_TIMEOUT) -> bytes:
    """Загрузка через curl: другой TLS-стек, помогает при части DPI-блокировок."""
    cmd = [
        "curl", "-sS", "-L",
        "--max-time", str(timeout),
        "--connect-timeout", str(max(3, timeout // 2)),
        "-A", _IMPORT_UA,
        "-o", "-",
        url,
    ]
    proxy = Settings.import_proxy()
    if proxy:
        cmd.extend(["--proxy", proxy])
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout + 5)
    except FileNotFoundError as e:
        raise FetchError("error", "curl не найден в системе") from e
    except subprocess.TimeoutExpired as e:
        raise FetchError("network", f"curl: таймаут {timeout}с") from e
    if r.returncode != 0:
        err = r.stderr.decode(errors="replace").strip()[:160]
        raise FetchError("network", f"curl (код {r.returncode}): {err}")
    return r.stdout


def fetch_url(url: str, *, use_etag: bool = True, allow_curl: bool = True,
              timeout: int = IMPORT_TIMEOUT) -> tuple[bytes, dict]:
    """Загружает подписку: urllib, при сетевом сбое — один раз curl.

    Повторяем только транзиентные сбои (сброс соединения, HTTP 429/5xx):
    таймаут или DNS-ошибка почти всегда означают недоступность сети целиком,
    и повтор той же попытки лишь съедает бюджет прогона.
    """
    attempts = 0
    last: FetchError | None = None
    while attempts < 2:
        attempts += 1
        try:
            return _fetch_urllib(url, use_etag=use_etag, timeout=timeout)
        except NotModified:
            raise
        except FetchError as e:
            last = e
            transient = (
                e.kind == "network" and "сброшено" in e.message
            ) or (e.http_status in (429, 500, 502, 503, 504))
            if transient and attempts < 2:
                time.sleep(1.0)
                continue
            break

    if allow_curl and last is not None and last.kind == "network":
        add_log("DEBUG", f"urllib failed for {url[:70]}: {last.message}; пробуем curl")
        try:
            return _fetch_curl(url), {"etag": "", "last_modified": "", "content_length": "",
                                      "content_type": "", "http_status": None, "via_curl": True}
        except FetchError as curl_err:
            raise FetchError("network", f"{last.message}; curl: {curl_err.message}") from curl_err
    raise last if last is not None else FetchError("error", "неизвестная ошибка загрузки")


# ─── Разбор и запись в БД ───


def _split_vless_lines(content: str) -> list[str]:
    """vless:// ссылки из контента; если их нет — пробуем base64-подписку."""
    lines = [ln.strip() for ln in content.splitlines() if ln.strip().startswith("vless://")]
    if lines:
        return lines
    try:
        decoded = base64.b64decode(content, validate=False).decode("utf-8", errors="replace")
    except Exception:
        return []
    return [ln.strip() for ln in decoded.splitlines() if ln.strip().startswith("vless://")]


def _schedule_enrichment() -> None:
    """Запускает определение стран для новых профилей (один прогон за раз).

    Вызывается из parse_and_store, поэтому работает и для одиночного импорта
    кнопкой, и для TXT-источников, и для прогона по всем источникам.
    """
    if not _ENRICH_LOCK.acquire(blocking=False):
        return

    def run():
        try:
            from .utils import enrich_all_unknown_countries

            enrich_all_unknown_countries()
        except Exception as e:
            add_log("DEBUG", f"Country enrichment failed: {e}")
        finally:
            _ENRICH_LOCK.release()

    threading.Thread(target=run, daemon=True).start()


def parse_and_store(content: str, *, source_id=None, label: str = "") -> dict:
    """Разбирает контент подписки и пишет прокси в БД.

    Возвращает счётчики: added, duplicates, skipped_unencrypted, parsed, deleted,
    no_links (True, если vless-ссылок не нашлось вовсе).
    """
    lines = _split_vless_lines(content)
    stats = {
        "added": 0, "duplicates": 0, "skipped_unencrypted": 0,
        "parsed": 0, "deleted": 0,
    }
    if not lines:
        stats["no_links"] = True
        add_log("WARN", f"No vless:// links found in content from {label} "
                        f"(content length={len(content)})")
        return stats
    stats["no_links"] = False

    safe_only = Settings.safe_only_import()
    seen: set[str] = set()
    valid_links: list[str] = []   # ссылки для вставки (после фильтра шифрования)
    source_links: list[str] = []  # все разобранные ссылки источника (для чистки)
    rows: list[tuple] = []
    for link in lines:
        if link in seen:
            continue
        seen.add(link)
        try:
            parsed = parse_vless(link)
        except Exception:
            # Одна нечитаемая строка не должна ломать разбор всего источника.
            parsed = None
        if not parsed:
            continue
        stats["parsed"] += 1
        source_links.append(link)
        sec = parsed.get("security", "none") or "none"
        if safe_only and sec == "none":
            stats["skipped_unencrypted"] += 1
            continue
        valid_links.append(link)
        rows.append(
            (link, parsed["host"], parsed["port"], parsed.get("country", ""),
             "pending", sec, now_utc(), source_id)
        )

    with _STORE_LOCK:
        conn = _get_conn()
        try:
            cur = conn.cursor()
            for row in rows:
                # rowcount отличает реальную вставку от сработавшего UNIQUE:
                # прежний код увеличивал счётчик на каждой итерации и показывал
                # «импортировано 200», даже когда в базу не попало ни одной записи.
                cur.execute(
                    "INSERT OR IGNORE INTO proxies "
                    "(link,host,port,country,status,security,added_at,source_id) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    row,
                )
                if cur.rowcount:
                    stats["added"] += 1
                else:
                    stats["duplicates"] += 1

            # Чистка устаревших идёт по ВСЕМ разобранным ссылкам источника, а не
            # по прошедшим фильтр шифрования: иначе при включённом «Безопасном
            # импорте» незашифрованные профили источника удалялись бы как
            # «исчезнувшие из подписки», хотя они в ней есть.
            if source_id is not None and source_links:
                placeholders = ",".join("?" * len(source_links))
                cur.execute(
                    f"DELETE FROM proxies WHERE source_id=? AND link NOT IN ({placeholders})",
                    [source_id] + source_links,
                )
                stats["deleted"] = cur.rowcount or 0
            conn.commit()
        finally:
            conn.close()

    if stats["deleted"]:
        add_log("INFO", f"Cleaned up {stats['deleted']} stale proxies for source #{source_id}")
    if stats["added"]:
        _schedule_enrichment()
    return stats


def _log_result(result: dict) -> None:
    """Одна строка лога на источник — понятная, без простыни исключений."""
    label = f"Импорт {result['name'] or '#' + str(result['id'])}"
    if result["status"] == STATUS_OK:
        parts = [f"новых {result['added']}"]
        if result["duplicates"]:
            parts.append(f"уже было {result['duplicates']}")
        if result["skipped_unencrypted"]:
            parts.append(f"без шифрования {result['skipped_unencrypted']}")
        add_log("INFO", f"{label}: ок ({', '.join(parts)})")
    elif result["status"] == STATUS_NOT_MODIFIED:
        add_log("DEBUG", f"{label}: без изменений (304)")
    elif result["status"] == STATUS_EMPTY:
        add_log("WARN", f"{label}: нет vless-ссылок в ответе")
    elif result["status"] in (STATUS_NETWORK_ERROR, STATUS_HTTP_ERROR, STATUS_BAD_URL, STATUS_ERROR):
        add_log("ERROR", f"{label}: {result['reason'] or status_label(result['status'])}")
    else:
        add_log("INFO", f"{label}: {status_label(result['status'])}")


# ─── Импорт одного источника ───


def import_url(url: str, source_id=None, **kwargs) -> dict:
    """Импортирует один URL-источник. Возвращает структурированный результат."""
    return _finish(_import_url(url, source_id, **kwargs))


def _import_url(url: str, source_id=None, *, label: str = "", use_etag: bool = True,
                allow_curl: bool = True, timeout: int = IMPORT_TIMEOUT) -> dict:
    started = time.monotonic()
    url = (url or "").strip().strip('"').strip("'")
    result = _result(source_id, label or url[:60], "url", STATUS_OK)
    if not url:
        result["status"] = STATUS_BAD_URL
        return _fail(result, "пустой URL")

    try:
        raw, meta = fetch_url(url, use_etag=use_etag, allow_curl=allow_curl, timeout=timeout)
    except NotModified:
        result["status"] = STATUS_NOT_MODIFIED
        result["seconds"] = round(time.monotonic() - started, 2)
        return result
    except FetchError as e:
        result["status"] = {
            "network": STATUS_NETWORK_ERROR,
            "http": STATUS_HTTP_ERROR,
            "bad_url": STATUS_BAD_URL,
        }.get(e.kind, STATUS_ERROR)
        result["http_status"] = e.http_status
        result["seconds"] = round(time.monotonic() - started, 2)
        return _fail(result, e.message)
    except Exception as e:  # неожиданный сбой не должен ронять весь прогон
        result["status"] = STATUS_ERROR
        result["seconds"] = round(time.monotonic() - started, 2)
        return _fail(result, f"{type(e).__name__}: {e}")

    _write_cache(url, meta.get("etag", ""), meta.get("last_modified", ""))
    result["http_status"] = meta.get("http_status")

    content = raw.decode("utf-8", errors="replace")
    stats = parse_and_store(content, source_id=source_id, label=url[:60])
    result.update(stats)
    result["seconds"] = round(time.monotonic() - started, 2)
    if stats.get("no_links"):
        result["status"] = STATUS_EMPTY
        return _fail(result, "в ответе нет vless:// ссылок")
    if not stats["parsed"]:
        # Ссылки были, но ни одна не разобралась: битый формат у источника.
        result["status"] = STATUS_EMPTY
        return _fail(result, "ни одна ссылка не разобралась")
    result["status"] = STATUS_OK
    return result


def import_txt(source_id, **kwargs) -> dict:
    """Импортирует TXT-источник из БД. Возвращает структурированный результат."""
    return _finish(_import_txt(source_id, **kwargs))


def _import_txt(source_id, *, label: str = "") -> dict:
    started = time.monotonic()
    result = _result(source_id, label, "txt", STATUS_OK)
    rows = db_q("SELECT name, content FROM sources WHERE id=?", (source_id,))
    if not rows:
        result["status"] = STATUS_ERROR
        return _fail(result, f"источник #{source_id} не найден")
    result["name"] = rows[0]["name"] or result["name"]
    content = (rows[0]["content"] or "").strip()
    if not content:
        result["status"] = STATUS_NO_CONTENT
        result["seconds"] = round(time.monotonic() - started, 2)
        return _fail(result, "у TXT-источника нет содержимого")

    stats = parse_and_store(content, source_id=source_id, label=f"txt://{result['name']}")
    result.update(stats)
    result["seconds"] = round(time.monotonic() - started, 2)
    if stats.get("no_links"):
        result["status"] = STATUS_EMPTY
        return _fail(result, "в содержимом нет vless:// ссылок")
    if not stats["parsed"]:
        # Как и для URL: строки вида vless:// есть, но ни одна не разобралась.
        result["status"] = STATUS_EMPTY
        return _fail(result, "ни одна ссылка не разобралась")
    result["status"] = STATUS_OK
    return result


def import_source(src: dict, *, allow_curl: bool = True, use_etag: bool = True) -> dict:
    """Импортирует источник по его записи из БД (единая точка входа)."""
    if not src:
        return _fail(_result(None, "", "", STATUS_ERROR), "источник не найден")
    if (src.get("type") or "url") == "txt":
        result = import_txt(src["id"], label=src.get("name") or "")
    else:
        result = import_url(
            src.get("url") or "", src.get("id"),
            label=src.get("name") or "", allow_curl=allow_curl, use_etag=use_etag,
        )
    _log_result(result)
    return result


def save_source_status(result: dict) -> None:
    """Сохраняет статус последнего импорта в записи источника.

    Статус `skipped` не сохраняется: это решение конкретного прогона
    (отмена, бюджет, предохранитель по сети), а не состояние источника.
    Иначе отменённый прогон затирал бы реальный исход карточки.
    """
    if not result or result.get("id") is None:
        return
    if result.get("status") == STATUS_SKIPPED:
        return
    reached = result.get("status") in REACHED_STATUSES
    try:
        if reached:
            db_q(
                "UPDATE sources SET last_import=?, last_status=?, last_error=? WHERE id=?",
                (now_utc(), result.get("status"), result.get("reason") or "", result["id"]),
            )
        else:
            db_q(
                "UPDATE sources SET last_status=?, last_error=? WHERE id=?",
                (result.get("status"), result.get("reason") or "", result["id"]),
            )
    except Exception as e:
        add_log("DEBUG", f"Could not save import status for source #{result['id']}: {e}")


# ─── Прогон по всем источникам ───


def summarize(results: list[dict]) -> dict:
    """Сводка прогона: счётчики по статусам и итоговые числа."""
    by_status: dict[str, int] = {}
    for r in results:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    return {
        "total": len(results),
        "added": sum(r["added"] for r in results),
        "duplicates": sum(r["duplicates"] for r in results),
        "skipped_unencrypted": sum(r["skipped_unencrypted"] for r in results),
        "deleted": sum(r["deleted"] for r in results),
        "ok": by_status.get(STATUS_OK, 0) + by_status.get(STATUS_NOT_MODIFIED, 0),
        "failed": sum(by_status.get(s, 0) for s in
                      (STATUS_NETWORK_ERROR, STATUS_HTTP_ERROR, STATUS_BAD_URL, STATUS_ERROR)),
        "empty": by_status.get(STATUS_EMPTY, 0) + by_status.get(STATUS_NO_CONTENT, 0),
        "skipped": by_status.get(STATUS_SKIPPED, 0),
        "by_status": by_status,
    }


def import_sources(sources: list[dict], *, budget_seconds: int = IMPORT_BUDGET_SEC,
                   network_break_after: int = NETWORK_BREAK_AFTER,
                   allow_curl: bool = True, use_etag: bool = True,
                   on_result=None, should_stop=None) -> dict:
    """Импортирует список источников с бюджетом времени и предохранителем по сети.

    Предохранитель: после `network_break_after` сетевых сбоев подряд остальные
    источники помечаются пропущенными без новых попыток. Это то, чего не хватало:
    при полностью недоступной сети прогон завершается за секунды с одной понятной
    причиной, а не висит минутами на каждом источнике по отдельности.

    `on_result` вызывается после каждого источника (прогресс), `should_stop`
    проверяется перед каждым (отмена прогона).

    Бюджет проверяется между источниками: отменить уже начатую загрузку нельзя,
    поэтому худший случай одной стадии — два сетевых сбоя подряд (первый с
    curl-фолбэком), то есть около минуты, после чего остальные источники
    пропускаются без обращений к сети. Без предохранителя это были минуты на
    каждый источник.
    """
    started = time.monotonic()
    deadline = started + max(5, budget_seconds)
    results: list[dict] = []
    network_failures = 0
    network_down = False
    curl_probe_done = not allow_curl

    for src in sources:
        src_type = src.get("type") or "url"
        # TXT-источники берутся из БД и сети не требуют: недоступная сеть —
        # не причина пропускать их вместе с URL-источниками.
        needs_network = src_type != "txt"
        if should_stop and should_stop():
            results.append(_fail(
                _result(src.get("id"), src.get("name"), src_type, STATUS_SKIPPED),
                "прогон отменён",
            ))
            continue
        if network_down and needs_network:
            results.append(_fail(
                _result(src.get("id"), src.get("name"), src_type, STATUS_SKIPPED),
                "сеть недоступна: пропущен, чтобы не держать блокировку замеров",
            ))
            continue
        if time.monotonic() > deadline:
            results.append(_fail(
                _result(src.get("id"), src.get("name"), src_type, STATUS_SKIPPED),
                f"бюджет времени импорта исчерпан ({budget_seconds}с)",
            ))
            continue

        result = import_source(
            src,
            allow_curl=(allow_curl and not curl_probe_done),
            use_etag=use_etag,
        )
        if result["status"] == STATUS_NETWORK_ERROR:
            # curl уже был опробован на первом сетевом сбое — дальше не тратим
            # на него время на каждом источнике.
            curl_probe_done = True
            network_failures += 1
            if network_failures >= network_break_after:
                network_down = True
        elif result["status"] in (STATUS_OK, STATUS_NOT_MODIFIED, STATUS_EMPTY):
            network_failures = 0

        results.append(result)
        if on_result:
            try:
                on_result(result)
            except Exception:
                pass

    if network_down:
        add_log(
            "ERROR",
            "Импорт остановлен: сеть недоступна у нескольких источников подряд. "
            "Проверьте сеть сервера или укажите «Прокси для импорта» в настройках "
            "(Раздел «Сеть»); диагностика — «Проверить связь» на странице источников.",
        )

    summary = summarize(results)
    summary["network_down"] = network_down
    summary["seconds"] = round(time.monotonic() - started, 2)
    summary["results"] = results
    add_log(
        "INFO" if not network_down else "WARN",
        f"Импорт завершён за {summary['seconds']}с: ok {summary['ok']}, "
        f"новых {summary['added']}, пусто {summary['empty']}, "
        f"ошибок {summary['failed']}, пропущено {summary['skipped']}",
    )
    return summary


# ─── Диагностика доступности ───


def _hint_for(step: str, message: str) -> str:
    """Подсказка по конкретному шагу проверки — что делать дальше."""
    from config import SOCKS_PORT

    own_inbound = (
        f"Если у Xray есть рабочие узлы, подойдёт собственный inbound: "
        f"socks5://127.0.0.1:{SOCKS_PORT}."
    )
    if step == "dns":
        return "DNS не разрешает имя: проверьте DNS сервера и доступность интернета."
    if step == "tcp":
        return ("TCP-порт недоступен: соединение режется (блокировка/DPI). "
                f"Укажите «Прокси для импорта» в настройках, раздел «Сеть». {own_inbound}")
    if step == "tls":
        return ("TLS-рукопожатие не проходит: похоже на DPI-блокировку этого домена. "
                f"Укажите «Прокси для импорта». {own_inbound}")
    if step == "http":
        if "404" in message or "410" in message:
            return "Источник устарел: ссылка больше не отдаёт файл, замените URL источника."
        if "403" in message:
            return "Источник отдаёт 403: возможно, блокировка или нужен User-Agent/прокси."
        return "Сервер ответил ошибкой: проверьте URL источника."
    return ""


def diagnose_url(url: str, *, timeout: int = 8) -> dict:
    """Пошаговая проверка источника: DNS → TCP → TLS → HTTP.

    Возвращает шаги с результатом и подсказку, что делать. Нужна, чтобы вместо
    «импорт не удался» пользователь видел, на каком именно шаге рвётся.
    """
    from urllib.parse import urlparse

    url = (url or "").strip()
    report = {
        "url": url,
        "steps": [],
        "ok": False,
        "hint": "",
        "import_proxy": Settings.import_proxy(),
        "curl_available": _curl_available(),
    }
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        report["steps"].append({"step": "url", "ok": False, "detail": "некорректный URL"})
        report["hint"] = "URL должен начинаться с http:// или https://"
        return report
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    t0 = time.monotonic()
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        ips = sorted({i[4][0] for i in infos})
        report["steps"].append({
            "step": "dns", "ok": True, "ms": int((time.monotonic() - t0) * 1000),
            "detail": ", ".join(ips[:4]),
        })
    except Exception as e:
        report["steps"].append({
            "step": "dns", "ok": False, "ms": int((time.monotonic() - t0) * 1000),
            "detail": f"{type(e).__name__}: {e}",
        })
        report["hint"] = _hint_for("dns", str(e))
        return report

    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        report["steps"].append({
            "step": "tcp", "ok": True, "ms": int((time.monotonic() - t0) * 1000),
            "detail": f"{host}:{port}",
        })
    except Exception as e:
        report["steps"].append({
            "step": "tcp", "ok": False, "ms": int((time.monotonic() - t0) * 1000),
            "detail": f"{type(e).__name__}: {e}",
        })
        report["hint"] = _hint_for("tcp", str(e))
        return report

    if parsed.scheme == "https":
        t0 = time.monotonic()
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                report["steps"].append({
                    "step": "tls", "ok": True, "ms": int((time.monotonic() - t0) * 1000),
                    "detail": f"{tls.version()}",
                })
                sock = None  # закрыт контекстом
        except Exception as e:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
            report["steps"].append({
                "step": "tls", "ok": False, "ms": int((time.monotonic() - t0) * 1000),
                "detail": f"{type(e).__name__}: {e}",
            })
            report["hint"] = _hint_for("tls", str(e))
            return report
    if sock is not None:
        sock.close()

    t0 = time.monotonic()
    try:
        # Диагностика читает только начало ответа: цель — понять, отвечает ли
        # сервер и отдаёт ли vless-ссылки, а не скачать подписку целиком.
        req = urllib.request.Request(
            url, headers={"User-Agent": _IMPORT_UA, "Range": "bytes=0-4095"}
        )
        with _build_opener().open(req, timeout=timeout) as r:
            head = r.read(4096)
            status_code = getattr(r, "status", 200)
            ctype = r.headers.get("Content-Type") or ""
        text = head.decode("utf-8", errors="replace")
        links = len(_split_vless_lines(text))
        report["steps"].append({
            "step": "http", "ok": True, "ms": int((time.monotonic() - t0) * 1000),
            "detail": f"HTTP {status_code}, {len(head)} байт, vless-ссылок в начале: {links}",
            "content_type": ctype,
        })
        report["ok"] = True
        if links == 0:
            report["hint"] = ("Сервер отвечает, но в начале ответа нет vless:// ссылок. "
                              "Если источник отдаёт base64-подписку, это нормально.")
    except urllib.error.HTTPError as e:
        message = f"HTTP {e.code}"
        report["steps"].append({
            "step": "http", "ok": False, "ms": int((time.monotonic() - t0) * 1000),
            "detail": message,
        })
        report["hint"] = _hint_for("http", message)
    except Exception as e:
        kind, message = _classify(e)
        report["steps"].append({
            "step": "http", "ok": False, "ms": int((time.monotonic() - t0) * 1000),
            "detail": message,
        })
        report["hint"] = _hint_for("http", message) or (
            "Соединение не проходит: похоже на блокировку. Укажите «Прокси для импорта»."
            if kind == "network" else ""
        )

    if report["ok"] and not report["import_proxy"]:
        report["hint"] = ("Источник доступен напрямую. Если импорт всё равно падает — "
                          "проверьте, что файл содержит vless:// ссылки.")
    return report


def _curl_available() -> bool:
    import shutil

    return shutil.which("curl") is not None
