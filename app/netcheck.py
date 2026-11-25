"""Подбор URL проверки и файла замера: «тест лучших ссылок» перед проверками.

Зачем это нужно
---------------
URL проверки (`probe_url`) используется в двух местах: чекер шлёт через
туннель HTTP-пробу, а observatory работающего Xray тем же URL проверяет
outbound-узлы. Если URL заблокирован у exit-нод, отдаёт ошибку или медленно
отвечает, все профили выглядят мёртвыми: панель не доходит до стадии замера
скорости. Это ровно та ситуация, когда «не импортирует / не проверяет».

Что делает модуль
-----------------
1. Держит каталог кандидатов — сервисы, которые реже блокируются: сначала
   лёгкие plain-HTTP `generate_204` (Cloudflare, Google, Firefox, GNOME,
   Microsoft), потом их HTTPS-варианты. Plain HTTP внутри туннеля не требует
   второго TLS-рукопожатия, поэтому отвечает быстрее и реже отваливается.
2. Умеет проверить кандидатов напрямую из панели и выбрать лучшего:
   `test_and_apply()`. Это ловит мёртвые сервисы, опечатки и блокировку URL
   на самом сервере.
3. Применяет выбранный URL в настройки; исправленный URL автоматически
   пересобирает конфиг Xray через обычный путь сохранения настроек (API).
4. Отдаёт список кандидатов чекеру: во время прогона он сам переключается на
   тот URL, который реально отвечает через туннели (см.
   `checker.ProbeUrlStats`), и запоминает лучший.

Проверка из панели не заменяет проверку через туннели: панель может достать
URL напрямую, а exit-нода — нет. Поэтому основной механизм выбора во время
прогона живёт в чекере, а этот модуль отвечает за каталог, ручной тест и
стартовую эвристику.
"""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .db import Settings
from .utils import add_log

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)

# Сертификаты не проверяем: для проверки живости URL важен сам факт ответа, а
# публичные точки проверки иногда отдают несовпадающий сертификат (msft).
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

# Каталог проб. Порядок — приоритет: чем выше, тем реже сервис блокируется и
# тем дешевле проба (plain HTTP без внутреннего TLS).
PROBE_URL_CANDIDATES: tuple[str, ...] = (
    "http://cp.cloudflare.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "http://www.gstatic.com/generate_204",
    "https://www.gstatic.com/generate_204",
    "http://connectivitycheck.gstatic.com/generate_204",
    "https://connectivitycheck.gstatic.com/generate_204",
    "http://detectportal.firefox.com/success.txt",
    "http://nmcheck.gnome.org/check_network_status.txt",
    "http://www.msftconnecttest.com/connecttest.txt",
)

# Каталог файлов замера скорости. Первым — Cloudflare: он отдаёт ровно
# запрошенное число байт и стабильно доступен с большинства exit-нод.
# Дальше — HTTPS-зеркала, затем plain HTTP: если у exit-нод режутся TLS/SNI
# или CONNECT-запросы, HTTPS-файлы «отвечают» мгновенной ошибкой, а HTTP-файл
# спокойно отдаёт байты (замеру скорости TLS не нужен).
SPEED_URL_CANDIDATES: tuple[str, ...] = (
    "https://speed.cloudflare.com/__down?bytes=10000000",
    # Российское зеркало: полезно, когда exit-нода в РФ и зарубежные CDN режутся.
    "https://speedtest.wcloud.ru/10MB",
    # Крупный стабильный файл Google: хорош для гигабитных каналов, где 10MB
    # заканчивается быстрее окна замера.
    "https://storage.googleapis.com/google-code-archive-downloads/"
    "v2/code.google.com/jquery-speedtest/100MB.txt",
    "https://storage.googleapis.com/google-code-archive-downloads/"
    "v2/code.google.com/jquery-speedtest/10MB.txt",
    # HuggingFace отдаёт файл через CDN; иногда доступен там, где Cloudflare
    # уже заблокирован.
    "https://huggingface.co/apple/DiffuCoder-7B-cpGRPO/resolve/refs%2Fpr%2F16/10-MB-Test.docx",
    "http://ftp.bit.nl/speedtest/10mb.bin",    "http://cachefly.cachefly.net/10mb.test",
    "http://mirror.yandex.ru/debian/ls-lR.gz",
    "http://mirror.yandex.ru/ubuntu/ls-lR.gz",
    "http://speedtest.selectel.ru/10MB",
    "http://speedtest.tele2.net/10MB.zip",
    "http://proof.ovh.net/files/10Mb.dat",
    "http://www.samplefiles.online/files/sample-10mb.bin",
    # Подписанная ссылка Google Drive: может истечь, поэтому последняя.
    "https://drive.usercontent.google.com/download"
    "?id=0B1MVW1mFO2zmdGhyaUJESWROQkE&export=download&authuser=0&confirm=t"
    "&uuid=4e0b9304-fdc7-4051-91a2-12d7292a0775"
    "&at=AMrWOn2eo2kdmlP3RLq9A156mIRU%3A1795592165521",
)

DEFAULT_SPEED_URL = SPEED_URL_CANDIDATES[0]

# Сколько кандидатов максимум отдавать чекеру: фоллбек пробуется только у
# упавших профилей, но каждый лишний кандидат — это лишний таймаут.
MAX_PROBE_CANDIDATES = 4

# Результаты последнего ручного теста живут в настройках, чтобы UI показывал
# их после перезагрузки страницы.
_LAST_TEST_KEY = "probe_url_last_test"
_PROBE_URL_CHECK_TTL = 6 * 3600  # перепроверять URL не чаще раза в 6 часов


# ─── Каталоги ───


def _split_candidates(raw: str) -> list[str]:
    """Разбирает список кандидатов из настройки: JSON-массив или строки/запятые."""
    raw = (raw or "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [str(x).strip() for x in data if str(x).strip()]
    except (ValueError, TypeError):
        pass
    parts = raw.replace("\r", "\n").replace(",", "\n").splitlines()
    return [p.strip() for p in parts if p.strip()]


def _user_probe_candidates() -> list[str]:
    """Кандидаты из настройки `probe_url_candidates` (пусто — встроенный каталог)."""
    return _split_candidates(Settings.get("probe_url_candidates", ""))


def _dedupe(urls) -> list[str]:
    """Оставляет только http(s)-URL без пустых значений и повторов."""
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        u = (u or "").strip()
        if not u or not u.lower().startswith(("http://", "https://")):
            continue
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out


def probe_url_catalog() -> list[str]:
    """Полный каталог проб: пользовательский список или встроенные кандидаты."""
    custom = _user_probe_candidates()
    return _dedupe(custom or list(PROBE_URL_CANDIDATES))


def probe_url_candidates(limit: int | None = None) -> list[str]:
    """URL для прогона: текущий первым, затем кандидаты каталога.

    `limit` ограничивает число кандидатов (по умолчанию MAX_PROBE_CANDIDATES),
    чтобы упавший профиль не выжидал таймаут на десятке провайдеров.
    """
    urls = _dedupe([Settings.probe_url()] + probe_url_catalog())
    cap = MAX_PROBE_CANDIDATES if limit is None else max(1, limit)
    return urls[:cap]


def speed_url_catalog() -> list[str]:
    """Каталог файлов замера: пользовательский список или встроенные."""
    custom = _split_candidates(Settings.get("speed_test_url_candidates", ""))
    return _dedupe(custom or list(SPEED_URL_CANDIDATES))


def speed_url_candidates() -> list[str]:
    """Файлы замера: текущий (как правило, Cloudflare) первым, затем запасные."""
    return _dedupe([Settings.get("speed_test_url", "")] + speed_url_catalog())


# ─── Прямая проверка URL из панели ───


def _direct_get(url: str, timeout: float, max_bytes: int = 65536,
                headers: dict | None = None) -> dict:
    """HTTP GET напрямую из панели. Возвращает ok/status/ms/bytes/error.

    ok=True для любого HTTP-ответа ниже 500: 403/404 доказывают, что сервис
    жив и отвечает, а не что URL мёртв. Так же считает и чекер через туннель.
    """
    started = time.time()
    hdrs = {"User-Agent": _UA}
    if headers:
        hdrs.update(headers)
    try:
        req = urllib.request.Request(url, headers=hdrs)
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            status = getattr(resp, "status", 200)
            try:
                data = resp.read(max_bytes) if max_bytes > 0 else b""
            except Exception:
                data = b""
            elapsed = time.time() - started
            return {
                "ok": status < 500,
                "status": status,
                "ms": int(elapsed * 1000),
                "bytes": len(data),
                "elapsed": elapsed,
                "error": "",
            }
    except urllib.error.HTTPError as e:
        elapsed = time.time() - started
        return {
            "ok": e.code < 500,
            "status": e.code,
            "ms": int(elapsed * 1000),
            "bytes": 0,
            "elapsed": elapsed,
            "error": f"HTTP {e.code}",
        }
    except Exception as e:  # noqa: BLE001 — причина нужна в отчёте
        return {
            "ok": False,
            "status": 0,
            "ms": int((time.time() - started) * 1000),
            "bytes": 0,
            "elapsed": time.time() - started,
            "error": (str(e) or type(e).__name__)[:120],
        }


def test_probe_url(url: str, timeout: float = 6.0) -> dict:
    """Проверяет один URL проверки напрямую из панели."""
    res = _direct_get(url, timeout, max_bytes=2048)
    return {"url": url, **res}


def test_speed_url(url: str, timeout: float = 8.0) -> dict:
    """Проверяет файл замера: Range-запрос 256 КБ и оценка скорости."""
    res = _direct_get(
        url,
        timeout,
        max_bytes=262144,
        headers={"Range": "bytes=0-262143"},
    )
    kbps = 0
    if res["ok"] and res["bytes"] and res["elapsed"] > 0:
        kbps = int((res["bytes"] * 8) / (res["elapsed"] * 1000))
    res["kbps"] = kbps
    return {"url": url, **res}


def measure_speed_direct(url: str, window_sec: int = 10) -> dict:
    """Полный прямой замер с панели (без профиля), avg + max.

    Нужен как baseline: если прямой замер быстрый, а профиль медленный —
    виноват узел/транспорт; если оба медленные — файл/канал панели.
    В отличие от test_speed_url не делает Range и не пишет в БД.
    """
    window_sec = max(1, min(300, int(window_sec)))
    started = time.time()
    deadline = started + window_sec
    timeout = max(8.0, min(60.0, window_sec + 5))
    total = 0
    peak = 0
    sample_t = started
    sample_total = 0
    status = 0
    error = ""

    def sample(now: float) -> None:
        """Обновляет пик скорости по окнам не короче 0.5 с."""
        nonlocal peak, sample_t, sample_total
        dt = now - sample_t
        if dt < 0.5:
            return
        delta = total - sample_total
        if delta > 0:
            peak = max(peak, int((delta * 8) / (dt * 1000)))
        sample_t = now
        sample_total = total

    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        resp = urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX)
        status = int(getattr(resp, "status", 200) or 200)
        try:
            while True:
                buf = resp.read(131072)
                if not buf:
                    if time.time() >= deadline:
                        break
                    try:
                        resp.close()
                        resp = urllib.request.urlopen(
                            req, timeout=timeout, context=_SSL_CTX
                        )
                        continue
                    except Exception as e:  # noqa: BLE001
                        error = f"reopen: {type(e).__name__}: {e}"
                        break
                total += len(buf)
                now = time.time()
                sample(now)
                if now >= deadline:
                    break
        finally:
            try:
                resp.close()
            except Exception:
                pass
    except urllib.error.HTTPError as e:
        status = e.code
        error = f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        error = f"{type(e).__name__}: {e}"
    elapsed = time.time() - started
    sample(time.time())
    avg = int((total * 8) / (elapsed * 1000)) if total > 0 and elapsed > 0 else 0
    peak = max(peak, avg)
    if not total and not error:
        error = "0 байт за окно"
    elif total < 4096 and not error:
        error = f"мало данных: {total} байт за {elapsed:.1f}с"
    return {
        "url": url,
        "ok": total >= 4096,
        "status": status,
        "avg_kbps": avg,
        "max_kbps": peak,
        "bytes": total,
        "elapsed": round(elapsed, 2),
        "error": error,
    }


def _run_parallel(urls: list[str], func, parallel: int = 6) -> list[dict]:
    """Параллельный тест кандидатов: последовательный ждал бы таймаут каждого."""
    if not urls:
        return []
    workers = max(1, min(parallel, len(urls)))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="url-test") as pool:
        futures = [pool.submit(func, u) for u in urls]
        return [f.result() for f in futures]


def _sort_results(results: list[dict]) -> list[dict]:
    """Лучшие первыми: 204, затем прочие ответы, затем ошибки; внутри — по ms."""

    def key(r: dict):
        """Ключ сортировки: 204, затем успешные, затем ошибки, внутри — по ms."""
        status = r.get("status") or 0
        if not r.get("ok"):
            tier = 3
        elif status == 204:
            tier = 0
        elif 200 <= status < 400:
            tier = 1
        else:
            tier = 2
        return (tier, r.get("ms") or 10**9)

    return sorted(results, key=key)


def test_probe_urls(urls: list[str] | None = None, timeout: float = 6.0,
                    parallel: int = 6) -> list[dict]:
    """Проверяет кандидатов URL проверки и сортирует по пригодности."""
    targets = _dedupe(urls or [Settings.probe_url()] + probe_url_catalog())
    results = _run_parallel(targets, lambda u: test_probe_url(u, timeout), parallel)
    return _sort_results(results)


def test_speed_urls(urls: list[str] | None = None, timeout: float = 8.0,
                    parallel: int = 3) -> list[dict]:
    """Проверяет кандидатов файла замера (Range-запрос, не весь файл)."""
    targets = _dedupe(urls or speed_url_candidates())
    results = _run_parallel(targets, lambda u: test_speed_url(u, timeout), parallel)
    return _sort_results(results)


def _best_url(results: list[dict], current: str = "") -> str:
    """Лучший URL: текущий, если он жив, иначе первый живой из отсортированных.

    Не меняем рабочий URL из-за пары миллисекунд: стабильность важнее
    микровыигрыша, а текущий URL уже выбран как менее блокируемый.
    """
    alive = [r for r in results if r.get("ok")]
    if not alive:
        return ""
    if current and any(r.get("url") == current for r in alive):
        return current
    return alive[0]["url"]


def remember_probe_url_test(results: list[dict]) -> None:
    """Запоминает результаты теста в настройках для UI и стартовой эвристики."""
    payload = {"ts": time.time(), "results": results}
    try:
        Settings.set(_LAST_TEST_KEY, json.dumps(payload, ensure_ascii=False))
    except Exception as e:  # noqa: BLE001 — тест URL не должен ронять панель
        add_log("DEBUG", f"Не удалось сохранить результаты теста URL: {e}")


def probe_url_last_test() -> dict:
    """Последний сохранённый тест URL (или пустой словарь)."""
    try:
        data = json.loads(Settings.get(_LAST_TEST_KEY, "") or "{}")
        if isinstance(data, dict) and isinstance(data.get("results"), list):
            return data
    except (ValueError, TypeError):
        pass
    return {}


_VERIFIED_KEY = "probe_url_verified"
_VERIFIED_TTL = 24 * 3600  # туннельное доказательство живёт сутки


def remember_tunnel_verified_url(url: str) -> None:
    """Запоминает URL, который реально отвечал через туннели в последнем прогоне.

    Это сильнее прямой проверки из панели: панель может не достать URL из-за
    собственных блокировок, а exit-ноды — достают.
    """
    if not url:
        return
    try:
        Settings.set(_VERIFIED_KEY, json.dumps({"url": url, "ts": time.time()}))
    except Exception as e:  # noqa: BLE001
        add_log("DEBUG", f"Не удалось сохранить проверенный через туннели URL: {e}")


def tunnel_verified_url() -> str:
    """URL, доказавший работоспособность через туннели недавно (или пусто)."""
    try:
        data = json.loads(Settings.get(_VERIFIED_KEY, "") or "{}")
    except (ValueError, TypeError):
        return ""
    if not isinstance(data, dict):
        return ""
    if (time.time() - float(data.get("ts") or 0)) > _VERIFIED_TTL:
        return ""
    return str(data.get("url") or "")


def apply_best_url(kind: str, results: list[dict]) -> str:
    """Применяет лучший URL каталога в настройки. Возвращает применённый URL.

    Пустая строка — менять нечего: текущий URL уже жив (его не трогаем).
    """
    key = "probe_url" if kind == "probe" else "speed_test_url"
    current = Settings.get(key, "") or ""
    best = _best_url(results, current)
    if kind == "probe":
        remember_probe_url_test(results)
    if not best or best == current:
        return ""
    Settings.set(key, best)
    label = "URL проверки" if kind == "probe" else "Файл замера"
    add_log("INFO", f"{label} переключён на лучший из теста: {best}")
    return best


def test_and_apply(kind: str = "probe", urls: list[str] | None = None,
                   timeout: float = 6.0, apply: bool = True) -> dict:
    """Тестирует кандидатов и (по умолчанию) применяет лучшего.

    Возвращает отчёт для API/UI: `results`, `best`, `applied`, `kind`.
    """
    kind = "speed" if kind == "speed" else "probe"
    if kind == "probe":
        results = test_probe_urls(urls, timeout=timeout)
        current = Settings.get("probe_url", "")
    else:
        results = test_speed_urls(urls, timeout=timeout)
        current = Settings.get("speed_test_url", "")
    # best пуст, если никто не ответил: не выдаём мёртвый текущий URL за «лучший».
    best = _best_url(results, current)
    applied = apply_best_url(kind, results) if apply else ""
    alive = sum(1 for r in results if r.get("ok"))
    add_log(
        "INFO",
        f"Тест URL ({'проверки' if kind == 'probe' else 'замера'}): "
        f"живых {alive}/{len(results)}, лучший {best or '—'}",
    )
    return {
        "kind": kind,
        "current": current,
        "best": best,
        "applied": applied,
        "results": results,
    }


# ─── Стартовая эвристика ───


def ensure_probe_url(timeout: float = 4.0) -> str:
    """Возвращает рабочий URL проверки, при необходимости подбирая лучший.

    Вызывается перед стадией проверки. Если текущий URL недавно проходил
    проверку — он возвращается сразу, без сети. `probe_url_auto=false`
    отключает автоподбор: используется ровно то, что указано в настройках.
    """
    current = Settings.probe_url()
    if not Settings.probe_url_auto():
        return current
    # URL, недавно доказавший работу через туннели, не перебиваем прямой
    # проверкой из панели: панель может быть заблокирована, а exit-ноды — нет.
    verified = tunnel_verified_url()
    if verified and verified == current:
        return current
    last = probe_url_last_test()
    if last and (time.time() - float(last.get("ts") or 0)) < _PROBE_URL_CHECK_TTL:
        ok_urls = {r.get("url") for r in last.get("results", []) if r.get("ok")}
        if current in ok_urls:
            return current
    results = test_probe_urls([current] + probe_url_catalog(), timeout=timeout)
    best = _best_url(results, current)
    if not best:
        add_log(
            "WARN",
            "URL проверки: ни один кандидат не ответил напрямую из панели — "
            f"оставляем {current}. Проверьте сеть сервера или «Прокси для импорта».",
        )
        return current
    remember_probe_url_test(results)
    if best != current:
        Settings.set("probe_url", best)
        add_log(
            "WARN",
            f"URL проверки: {current} не отвечает из панели — переключён на {best}. "
            "Это влияет на проверку узлов и на observatory Xray.",
        )
    return best
