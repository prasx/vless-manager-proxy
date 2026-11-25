"""Массовая проверка прокси быстрым способом.

Раньше каждый прокси проверялся отдельным процессом Xray: старт процесса,
ожидание его порта, проба, остановка. На прогоне из 1000 профилей это давало
~1.4 профиля в секунду, потому что 85 % мёртвых нод честно выжидают полный
таймаут, а всё остальное время уходит на запуск/остановку процессов.

Здесь два уровня ускорения:

1. TCP-префильтр — до запуска Xray проверяем, вообще ли открыт server:port.
   Для мёртвого адреса это 1–2 с вместо таймаута пробы через туннель.
2. Батч-чекер — один процесс Xray обслуживает пачку профилей: на каждый
   профиль свой http-inbound на локальном порту и свой vless-outbound,
   routing связывает их по inboundTag. Пробы идут параллельно, процессы
   на профиль больше не запускаются.

Если Xray отказался стартовать из-за одного битого конфига в пачке, пачка
делится пополам (bisect) и виновник в итоге помечается точной причиной.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import (
    ThreadPoolExecutor,
    TimeoutError as FuturesTimeoutError,
    as_completed,
)
from pathlib import Path

from . import netcheck
from .db import Settings
from .utils import add_log
from .vless import is_known_network, normalize_network, sanitize_flow, stream_settings

# Сколько ждать, пока Xray поднимет все inbounds пачки, секунд.
# Пачка может быть 128-256 профилей: на медленном VPS старт занимает дольше.
STARTUP_TIMEOUT = 15.0

# Диапазон локальных портов для inbounds батч-чекера.
PORT_RANGE_START = 20000
PORT_RANGE_END = 40000

# Транспорты, которые умеет собирать stream_settings().
KNOWN_NETWORKS = frozenset(
    {"tcp", "ws", "grpc", "kcp", "h2", "http", "xhttp", "quic", "httpupgrade"}
)


# ─── Ошибки проб ───


def describe_probe_error(e: BaseException) -> str:
    """Превращает исключение HTTP-пробы в короткую человекочитаемую причину."""
    if isinstance(e, urllib.error.HTTPError):
        return f"http {e.code}"
    reason = e.reason if isinstance(e, urllib.error.URLError) else e
    msg = str(reason)
    low = msg.lower()
    if "timed out" in low or "timeout" in low:
        return "timeout"
    if "refused" in low:
        return "connection refused"
    if "reset" in low or "disconnected" in low or "aborted" in low:
        return "connection reset"
    if "getaddrinfo" in low or "name or service not known" in low:
        return "dns lookup failed"
    if "tls" in low or "ssl" in low or "certificate" in low:
        return "tls error"
    return (msg or type(e).__name__)[:100]


def _median(values: list[int]) -> int:
    """Медиана списка чисел (пустой список → 0)."""
    if not values:
        return 0
    s = sorted(values)
    n = len(s)
    if n % 2:
        return s[n // 2]
    return int((s[n // 2 - 1] + s[n // 2]) / 2)


def _opener_for_port(http_port: int) -> urllib.request.OpenerDirector:
    proxy_url = f"http://127.0.0.1:{http_port}"
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    )


# 503 от http-inbound Xray — это ошибка dial внутри Xray, а не ответ сервиса.
# Настоящий 503 сервиса (с текстом обслуживания) тоже не доказывает egress,
# но не даёт повода считать узел мёртвым; отличаем по тексту dial-ошибки.
_PROXY_DIAL_ERROR_MARKERS = (
    "failed to dial",
    "dial tcp",
    "connection refused",
    "i/o timeout",
    "no such host",
    "tls handshake",
    "connection reset by peer",
    "context deadline exceeded",
    "proxy dial failed",
    "failed to read response",
)


def _is_proxy_dial_error(body: str) -> bool:
    low = (body or "").lower()
    return any(marker in low for marker in _PROXY_DIAL_ERROR_MARKERS)


def probe_once(http_port: int, timeout: float, probe_url: str) -> tuple[bool, int, str, float]:
    """Одна HTTP-проба через локальный http-inbound.

    Возвращает (ok, latency_ms, error, elapsed_sec).

    Живым считается не только HTTP-ответ, но и **реально полученное тело**:
    DPI/фейковый узел умеет отдать заголовки 200 и оборвать поток. Раньше такая
    handshake-only нода считалась рабочей, а замер скорости у неё всегда был 0.
    Для 204/304 тела нет по стандарту — их пропускаем без проверки.
    """
    req_timeout = max(1.0, timeout)
    started = time.time()
    try:
        resp = _opener_for_port(http_port).open(probe_url, timeout=req_timeout)
        status = int(getattr(resp, "status", 0) or 0)
        body = b""
        try:
            if status not in (204, 304):
                # 64 байт достаточно, чтобы отличить живой поток от одних
                # заголовков; полный ответ для проверки не нужен.
                body = resp.read(64)
        finally:
            try:
                resp.close()
            except Exception:
                pass
        if status not in (204, 304) and not body:
            return False, 0, "empty body (handshake only)", time.time() - started
        # Не меньше 1 мс: latency_vless > 0 — условие попадания в конфиг,
        # а округление быстрого ответа до 0 исключило бы живой профиль.
        latency_ms = max(1, int((time.time() - started) * 1000))
        return True, latency_ms, "", time.time() - started
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(400).decode("utf-8", "replace").strip()
        except Exception:
            pass
        if e.code >= 500:
            if _is_proxy_dial_error(body):
                return (
                    False,
                    0,
                    f"proxy dial failed: {body[:120]}",
                    time.time() - started,
                )
            if not body:
                return False, 0, f"http {e.code}: no body", time.time() - started
            # Настоящий 5xx сервиса с телом: egress дошёл до сервиса.
            latency_ms = max(1, int((time.time() - started) * 1000))
            return True, latency_ms, "", time.time() - started
        # 4xx — реальный ответ сервиса, туннель и egress живы.
        latency_ms = max(1, int((time.time() - started) * 1000))
        return True, latency_ms, "", time.time() - started
    except Exception as e:  # noqa: BLE001 — нужна человекочитаемая причина
        return False, 0, describe_probe_error(e), time.time() - started


class ProbeUrlStats:
    """Счётчики ответов по URL пробы — по ним выбирается рабочий URL.

    Идея «теста лучших ссылок для остальных проверок»: первый же профиль,
    прошедший через туннель, показывает, какой URL реально отвечает у
    exit-нод. Счётчики копятся по мере прогона, а `ordered()` возвращает URL,
    отсортированные по доле успешных проб: остальные профили проверяются уже
    через рабочий URL.
    """

    def __init__(self, urls):
        self._lock = threading.Lock()
        self._urls = list(dict.fromkeys(u for u in (urls or []) if u))
        self._ok: dict[str, int] = {u: 0 for u in self._urls}
        self._fail: dict[str, int] = {u: 0 for u in self._urls}
        self._errors: dict[str, dict[str, int]] = {u: {} for u in self._urls}

    def record(self, url: str, ok: bool, error: str = "") -> None:
        with self._lock:
            if url not in self._ok:
                self._urls.append(url)
                self._ok[url] = 0
                self._fail[url] = 0
                self._errors[url] = {}
            if ok:
                self._ok[url] += 1
            else:
                self._fail[url] += 1
                if error:
                    bucket = self._errors[url]
                    bucket[error] = bucket.get(error, 0) + 1

    def ordered(self) -> list[str]:
        """URL по убыванию пригодности: сглаженная доля успеха, затем объём."""
        with self._lock:
            urls = list(self._urls)
            ok = dict(self._ok)
            fail = dict(self._fail)
        index = {u: i for i, u in enumerate(urls)}

        def score(u: str):
            ratio = (ok[u] + 1) / (ok[u] + fail[u] + 2)  # сглаживание: 0 проб = 0.5
            return (-ratio, -ok[u], index[u])

        return sorted(urls, key=score)

    def ok_count(self, url: str) -> int:
        with self._lock:
            return self._ok.get(url, 0)

    def attempts(self, url: str) -> int:
        with self._lock:
            return self._ok.get(url, 0) + self._fail.get(url, 0)

    def total(self) -> int:
        with self._lock:
            return sum(self._ok.values()) + sum(self._fail.values())

    def best(self) -> str:
        """URL с наибольшим числом успехов (или пусто, если успехов не было)."""
        with self._lock:
            urls = list(self._urls)
            ok = dict(self._ok)
            fail = dict(self._fail)
        ranked = [u for u in urls if ok[u] > 0]
        if not ranked:
            return ""
        ranked.sort(
            key=lambda u: (-ok[u], -(ok[u] / max(1, ok[u] + fail[u])), urls.index(u))
        )
        return ranked[0]

    def summary(self, limit: int = 6) -> str:
        """Короткая сводка «url: ok/attempts» для логов и прогресса."""
        with self._lock:
            urls = list(self._urls)
            ok = dict(self._ok)
            fail = dict(self._fail)
        parts = []
        for u in self.ordered()[:limit]:
            attempts = ok[u] + fail[u]
            if not attempts:
                continue
            parts.append(f"{u}: {ok[u]}/{attempts}")
        return ", ".join(parts)


def _as_url_list(probe_urls) -> list[str]:
    """Принимает строку или список URL пробы и возвращает непустой список."""
    if isinstance(probe_urls, str):
        return [probe_urls] if probe_urls.strip() else []
    return [u for u in (probe_urls or []) if u and str(u).strip()]


def probe_median(
    http_port: int,
    timeout: float,
    probe_urls,
    samples: int = 3,
    cancel: threading.Event | None = None,
    retries: int | None = None,
    stats: "ProbeUrlStats | None" = None,
) -> tuple[bool, int, str, int]:
    """Проверка профиля: первая проба решает «жив/мёртв», затем ещё пробы для медианы.

    `probe_urls` — строка или список кандидатов. Порядок кандидатов берётся из
    `stats` (какой URL работает у exit-нод), план попыток:
      1. рабочий URL, таймаут из настроек;
      2. следующий кандидат (или тот же URL, если кандидат один) с таймаутом
         ×1.5 — медленные и защищённые серверы отвечают не сразу;
      3. при `probe_retries >= 2` — рабочий URL с таймаутом ×2.
    Возвращает (ok, latency_ms, error, samples_ok).
    """
    urls = _as_url_list(probe_urls)
    if stats is not None:
        ordered = stats.ordered()
        if ordered:
            urls = ordered
    if not urls:
        return False, 0, "no probe url", 0
    if retries is None:
        retries = Settings.probe_retries()
    retries = max(0, min(3, int(retries)))
    base_timeout = max(1.0, float(timeout))

    # План: чередуем кандидатов, увеличивая таймаут на каждой попытке.
    plan: list[tuple[str, float]] = []
    for i in range(1 + retries):
        url = urls[i] if i < len(urls) else urls[0]
        plan.append((url, base_timeout * (1 + 0.5 * i)))

    last_err = "timeout"
    for url, attempt_timeout in plan:
        if cancel and cancel.is_set():
            return False, 0, "canceled", 0
        ok, lat, err, _elapsed = probe_once(http_port, attempt_timeout, url)
        if stats is not None:
            stats.record(url, ok, err)
        if ok:
            lats = [lat]
            for _ in range(max(0, samples - 1)):
                if cancel and cancel.is_set():
                    break
                ok2, lat2, _err2, _ = probe_once(http_port, base_timeout, url)
                if stats is not None:
                    stats.record(url, ok2, _err2)
                if ok2:
                    lats.append(lat2)
            return True, _median(lats), "", len(lats)
        if err:
            last_err = err
    return False, 0, last_err, 0


def tcp_reachable(host: str, port: int, timeout: float) -> tuple[bool, str]:
    """Быстрая проверка TCP-доступности server:port без Xray."""
    if not host or not port:
        return False, "tcp unreachable"
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True, ""
    except socket.gaierror:
        return False, "dns lookup failed"
    except socket.timeout:
        return False, "tcp timeout"
    except ConnectionRefusedError:
        return False, "tcp refused"
    except OSError as e:
        low = str(e).lower()
        if "refused" in low:
            return False, "tcp refused"
        if "timed out" in low:
            return False, "tcp timeout"
        return False, "tcp unreachable"


def validate_link(parsed: dict | None) -> str | None:
    """Проверяет, что из ссылки получится заведомо валидный outbound Xray.

    Возвращает причину отказа или None. Нужна, чтобы один битый профиль не
    валил старт целой пачки батч-чекера.
    """
    if not parsed:
        return "invalid link"
    if not parsed.get("server") or not parsed.get("uid"):
        return "invalid link"
    try:
        port = int(parsed.get("port") or 0)
    except (TypeError, ValueError):
        return "invalid port"
    if not (0 < port < 65536):
        return "invalid port"
    # Нормализуем псевдонимы (raw → tcp, splithttp → xhttp) прямо в parsed:
    # дальше по конвейеру build_outbound берёт транспорт уже из него.
    net = normalize_network(parsed.get("type"))
    parsed["type"] = net
    if not is_known_network(net):
        return f"unsupported transport: {net}"
    if parsed.get("security") == "reality":
        pbk = (parsed.get("pbk") or parsed.get("publicKey") or "").strip()
        if not pbk or _b64_len(pbk) != 32:
            return "invalid reality publicKey"
    return None


def _b64_len(value: str) -> int:
    """Длина base64url-строки в байтах (для проверки reality publicKey)."""
    try:
        raw = value.replace("-", "+").replace("_", "/")
        return len(base64.b64decode(raw + "=" * (-len(raw) % 4), validate=False))
    except Exception:
        return -1


# ─── Порты ───


class PortReserver:
    """Выдаёт свободные локальные порты и не отдаёт один порт дважды.

    Раньше порт брался у ОС и тут же освобождался, а Xray биндил его позже:
    при параллельных проверках проба могла уйти в чужой туннель — отсюда
    ложные «works/failed». Здесь порт проверяется на занятость и резервируется
    до конца пачки.
    """

    def __init__(self, start: int = PORT_RANGE_START, end: int = PORT_RANGE_END):
        self._next = start
        self._end = end
        self._lock = threading.Lock()

    def reserve(self, count: int) -> list[int]:
        """Резервирует count свободных портов (или меньше, если диапазон кончился)."""
        ports: list[int] = []
        span = max(1, self._end - PORT_RANGE_START)
        with self._lock:
            attempts = 0
            while len(ports) < count and attempts < span:
                attempts += 1
                port = self._next
                self._next += 1
                if self._next >= self._end:
                    self._next = PORT_RANGE_START
                if self._is_free(port):
                    ports.append(port)
        return ports

    @staticmethod
    def _is_free(port: int) -> bool:
        # Без SO_REUSEADDR: на Windows он позволяет занять уже слушающий порт,
        # и тогда проба уйдёт в чужой туннель (ровно та ошибка, которую порты
        # и должны исключить).
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


# ─── Запуск процесса Xray ───


class SubprocessLauncher:
    """Запускает Xray отдельной группой процессов (чтобы убивать вместе с детьми)."""

    def __init__(self, xray_bin: str):
        self.xray_bin = xray_bin

    def start(self, config_path: str, log_path: str) -> subprocess.Popen:
        log = open(log_path, "wb")
        try:
            return subprocess.Popen(
                [self.xray_bin, "run", "-c", config_path],
                stdout=subprocess.DEVNULL,
                stderr=log,
                start_new_session=True,
            )
        finally:
            log.close()

    @staticmethod
    def stop(proc: subprocess.Popen) -> None:
        if proc is None:
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except Exception:
            try:
                proc.terminate()
            except Exception:
                pass
        try:
            proc.wait(timeout=3)
        except Exception:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                pass


class BatchXrayChecker:
    """Проверяет пачки профилей одним процессом Xray на пачку."""

    def __init__(self, launcher: SubprocessLauncher | None = None,
                 port_reserver: PortReserver | None = None):
        self._launcher = launcher
        self._ports = port_reserver or PortReserver()
        self._current_proc = None
        self._proc_lock = threading.Lock()
        self._probe_url_snapshot: list[str] = []
        # Статистика ответов по URL пробы за последний прогон: по ней
        # выбирается рабочий URL и объясняется «почему все мёртвые».
        self.last_probe_stats: ProbeUrlStats | None = None
        # None — ещё не пробовали, True/False — поддерживает ли бинарник
        # быструю проверку конфига (`xray run -test`).
        self._config_test_supported: bool | None = None
        # True — пачку уже проверили поштучно перед запуском, повторный тест
        # целой пачки не нужен.
        self._skip_chunk_test = False
        # Причина последнего отказа старта: "config" (конфиг отклонён Xray)
        # или "start" (процесс не поднялся по другой причине).
        self._last_start_kind = "start"

    # ─── Публичный API ───

    def check(
        self,
        items: list[tuple[int, dict]],
        *,
        timeout: float,
        batch_size: int | None = None,
        cancel: threading.Event | None = None,
        on_result=None,
        start_concurrency: int | None = None,
        probe_urls: list[str] | None = None,
        batch_limit: float | None = None,
    ) -> dict[int, dict]:
        """Проверяет профили, возвращает {id: {ok, latency, error, samples}}.

        items — список (id, parsed). batch_size — сколько профилей в одном
        процессе Xray; они же проверяются параллельно. on_result(key, result)
        вызывается по мере готовности (прогресс и запись в БД).

        probe_urls — кандидаты URL проверки. Чекер пробует их по очереди у
        упавших профилей и по ходу прогона ставит вперёд тот, что отвечает
        через туннели (см. ProbeUrlStats).

        batch_limit — страховка от зависания: если пачка не уложилась в это
        время (застрявшие сокеты, «повисший» Xray), оставшиеся профили
        помечаются причиной «probe batch timeout», а конвейер идёт дальше.
        """
        results: dict[int, dict] = {}
        if not items:
            return results
        batch_size = max(1, int(batch_size or Settings.check_batch_size()))
        timeout = max(1.0, float(timeout))
        urls = probe_urls if probe_urls else netcheck.probe_url_candidates()
        self._probe_url_snapshot = list(urls)
        self.last_probe_stats = ProbeUrlStats(urls)
        samples = Settings.ping_samples()

        # Нет бинарника Xray — не пытаемся запускать процесс для каждой пачки и
        # каждого профиля при bisect: это тысячи неудачных Popen и лавина логов.
        # Сразу отдаём точную причину, конвейер продолжится без проверки.
        xbin = Settings.xray_bin()
        if self._launcher is None and not Path(xbin).is_file() and not shutil.which(xbin):
            error = f"xray binary not found: {xbin}"
            add_log("ERROR", f"Check skipped: {error}")
            for key, _parsed in items:
                result = {"ok": False, "latency": 0, "error": error, "samples": 0}
                results[key] = result
                if on_result:
                    try:
                        on_result(key, result)
                    except Exception:  # noqa: BLE001
                        pass
            return results

        # Поштучная предпроверка конфигов ДО батчей. Раньше при одном битом
        # профиле в пачке чекер делил её пополам, тестировал половины и снова
        # запускал Xray — на сервере это давало пачки по 150–300 с и лавину
        # «конфиг пачки отклонён». Одиночные тесты дёшевы и параллелятся,
        # а после них в батчи попадают только заведомо валидные профили.
        items = self._prevalidate_configs(items, results, on_result, cancel)
        if not items:
            return results

        # Страховка от зависания одной пачки: старт Xray + все попытки проб
        # с запасом. Если пачка не уложилась — помечаем остаток timeout'ом и
        # идём дальше, а не стоим навсегда.
        if batch_limit is None:
            retries = Settings.probe_retries()
            batch_limit = max(
                120.0,
                STARTUP_TIMEOUT + timeout * (samples + 2 * retries + 3) + 45,
            )

        batches = list(range(0, len(items), batch_size))
        for index, start in enumerate(batches, start=1):
            if cancel and cancel.is_set():
                break
            if sys.is_finalizing():
                # Интерпретатор уже завершается: новые futures запрещены.
                break
            chunk = items[start:start + batch_size]
            add_log(
                "DEBUG",
                f"Check batch {index}/{len(batches)}: {len(chunk)} профилей",
            )
            batch_started = time.monotonic()
            # Бюджет на ЗАПУСК Xray внутри пачки: при битом конфиге чекер
            # делит пачку пополам и снова стартует процесс. Без бюджета
            # пачка из 128 «плохих» профилей могла висеть на стартах десятки
            # минут (до 255 попыток по 15 с), и прогон выглядел зависшим.
            start_deadline = batch_started + max(90.0, STARTUP_TIMEOUT * 4)
            self._check_chunk(
                chunk, timeout, self.last_probe_stats, samples, cancel, on_result,
                results, concurrency=start_concurrency, batch_limit=batch_limit,
                start_deadline=start_deadline,
            )
            add_log(
                "DEBUG",
                f"Check batch {index}/{len(batches)}: готово за "
                f"{time.monotonic() - batch_started:.1f}с",
            )
        return results

    def kill_current(self) -> None:
        """Аварийно убивает текущий процесс чека (вызывается при shutdown)."""
        with self._proc_lock:
            proc = self._current_proc
            self._current_proc = None
        if proc is not None:
            self._stop(proc, None, None)

    # ─── Внутреннее ───

    def _launcher_or_default(self) -> SubprocessLauncher:
        if self._launcher is not None:
            return self._launcher
        return SubprocessLauncher(Settings.xray_bin())

    def _check_chunk(self, chunk, timeout, probe_stats, samples, cancel,
                     on_result, results, concurrency=None, batch_limit=None,
                     start_deadline=None) -> None:
        """Проверяет одну пачку; при отказе старта делит её пополам."""
        if cancel and cancel.is_set():
            return

        def report_failed(chunk_items, error: str) -> None:
            for key, _parsed in chunk_items:
                result = {"ok": False, "latency": 0, "error": error, "samples": 0}
                results[key] = result
                if on_result:
                    try:
                        on_result(key, result)
                    except Exception as e:  # noqa: BLE001
                        add_log("DEBUG", f"Check result callback failed for #{key}: {e}")

        started = self._start_chunk(chunk)
        if started is None:
            error = self._last_start_error or "xray start failed"
            config_error = self._last_start_kind == "config"
            # Бюджет ограничивает только «медленные» старты процесса. Битый
            # конфиг отсекается быстрой проверкой, деление пачки для него
            # дешёвое — изолируем виновника всегда, сколько бы профилей ни было.
            if (
                not config_error
                and start_deadline
                and time.monotonic() > start_deadline
            ):
                # Бюджет стартов пачки исчерпан: дальше деление пополам даст
                # ещё десятки медленных попыток. Помечаем остаток и идём дальше.
                add_log(
                    "WARN",
                    f"Check: исчерпан бюджет запуска Xray на пачку — "
                    f"{len(chunk)} профилей помечены «{error}», прогон продолжается",
                )
                report_failed(chunk, error)
                return
            if len(chunk) > 1:
                mid = len(chunk) // 2
                self._check_chunk(chunk[:mid], timeout, probe_stats, samples,
                                  cancel, on_result, results, concurrency,
                                  batch_limit, start_deadline)
                if cancel and cancel.is_set():
                    return
                self._check_chunk(chunk[mid:], timeout, probe_stats, samples,
                                  cancel, on_result, results, concurrency,
                                  batch_limit, start_deadline)
            else:
                report_failed(chunk, error)
            return
        proc, ports, tmp_path, log_path = started
        if cancel and cancel.is_set():
            # Отмена: профили пачки остаются непроверенными (не «failed»).
            self._stop(proc, tmp_path, log_path)
            return
        try:
            self._probe_chunk(chunk, ports, timeout, probe_stats, samples,
                              cancel, on_result, results, concurrency,
                              batch_limit)
        finally:
            self._stop(proc, tmp_path, log_path)

    _last_start_error: str = ""

    def _xray_bin(self) -> str:
        launcher = self._launcher_or_default()
        return getattr(launcher, "xray_bin", "") or Settings.xray_bin()

    def _test_config(self, path: str) -> tuple[bool, str]:
        """Быстрая проверка конфига: `xray run -test -c file` (без запуска).

        Без неё битый outbound в пачке обнаруживался только запуском процесса:
        Xray стартовал и падал, чекер делил пачку пополам, и на нескольких
        «плохих» конфигах бюджет запуска успевал кончиться — часть живых
        профилей помечалась «xray start failed». Проверка конфига занимает
        десятки миллисекунд и позволяет отсеять только битые профили.
        """
        if self._config_test_supported is False:
            return True, ""
        xbin = self._xray_bin()
        # Сначала «старый» синтаксис: современный Xray поддерживает его через
        # режим совместимости (main.go добавляет `run`), а древние версии знают
        # только его. Второй вариант — явный `run -test -c` для новых сборок.
        commands = (
            [xbin, "-test", "-config", path],
            [xbin, "run", "-test", "-c", path],
        )
        for index, cmd in enumerate(commands):
            try:
                r = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10
                )
            except (OSError, subprocess.SubprocessError) as e:
                # Бинарник не найден / тест-режим недоступен — работаем по старому.
                self._config_test_supported = False
                add_log("DEBUG", f"Config pre-test недоступен: {e}")
                return True, ""
            out = (r.stdout or "").strip()
            err = (r.stderr or "").strip()
            combined = err or out
            if r.returncode == 0:
                self._config_test_supported = True
                return True, ""
            # Старая версия Xray не знает `run -test` — пробуем второй вариант,
            # затем отключаем предпроверку и живём как раньше.
            if "flag provided but not defined" in combined:
                if index == 0:
                    continue
                self._config_test_supported = False
                add_log("DEBUG", f"Config pre-test не поддерживается: {combined[:120]}")
                return True, ""
            # Xray печатает причину в stdout («Failed to start: …»), а не только
            # в stderr — без этого в логах было бесполезное «без деталей».
            lines = [ln for ln in combined.splitlines() if ln.strip()]
            detail = lines[-1][:200] if lines else ""
            return False, detail
        self._config_test_supported = False
        return True, ""

    def _prevalidate_configs(self, items, results, on_result, cancel):
        """Проверяет конфиг каждого профиля поодиночке (параллельно).

        Возвращает только валидные профили; битые сразу помечаются failed с
        точной причиной от Xray. После этого в батчи попадают только рабочие
        конфиги и деление пачки пополам (bisect) вообще не нужно.
        """
        self._skip_chunk_test = False
        if not items or self._config_test_supported is False:
            return items

        def test_one(item):
            key, parsed = item
            ports = self._ports.reserve(1)
            if not ports:
                return item, True, ""
            cfg = self._build_config([(key, parsed)], ports)
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
            path = Path(tmp.name)
            try:
                with tmp:
                    json.dump(cfg, tmp)
                ok, detail = self._test_config(str(path))
            finally:
                try:
                    path.unlink(missing_ok=True)
                except Exception:
                    pass
            return item, ok, detail

        def handle(item, ok, detail):
            if ok:
                return True
            key = item[0]
            error = f"xray config invalid: {detail}" if detail else "xray config invalid"
            result = {"ok": False, "latency": 0, "error": error, "samples": 0}
            results[key] = result
            if on_result:
                try:
                    on_result(key, result)
                except Exception as e:  # noqa: BLE001
                    add_log("DEBUG", f"Check result callback failed for #{key}: {e}")
            return False

        started = time.monotonic()
        add_log(
            "DEBUG",
            f"Check: предпроверка конфигов {len(items)} профилей (параллельно)…",
        )
        first_item, first_ok, first_detail = test_one(items[0])
        if self._config_test_supported is False:
            # Бинарник не поддерживает -test — работаем по-старому.
            return items
        valid: list = []
        rest = items[1:]
        workers = max(1, min(8, len(rest) or 1))
        if handle(first_item, first_ok, first_detail):
            valid.append(first_item)
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="cfgtest") as pool:
            for item, ok, detail in pool.map(test_one, rest):
                if cancel and cancel.is_set():
                    # Отмена: непроверенные не превращаем в failed.
                    valid.append(item)
                    continue
                if handle(item, ok, detail):
                    valid.append(item)
        self._skip_chunk_test = True
        invalid = len(items) - len(valid)
        message = (
            f"Check: конфиги проверены — валидных {len(valid)}/{len(items)}, "
            f"отклонено {invalid}, за {time.monotonic() - started:.1f}с"
        )
        add_log("INFO" if invalid else "DEBUG", message)
        return valid

    def _start_chunk(self, chunk):
        """Запускает Xray для пачки. Возвращает (proc, ports, tmp_path, log_path) или None."""
        self._last_start_kind = "start"
        ports = self._ports.reserve(len(chunk))
        if len(ports) < len(chunk):
            self._last_start_error = "no free local ports"
            return None
        config = self._build_config(chunk, ports)
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        tmp.write(json.dumps(config))
        tmp.close()
        tmp_path = Path(tmp.name)

        log_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False, prefix="xray-batch-"
        )
        log_file.close()
        log_path = Path(log_file.name)

        # Сначала быстрая проверка конфига: битый профиль отсекается без
        # запуска процесса и без ожидания таймаута старта. Если профили уже
        # проверены поштучно, повторять тест целой пачки не нужно.
        if not self._skip_chunk_test:
            ok, detail = self._test_config(str(tmp_path))
            if not ok:
                self._last_start_kind = "config"
                self._last_start_error = (
                    f"xray config invalid: {detail}" if detail else "xray config invalid"
                )
                add_log(
                    "DEBUG",
                    f"Check: конфиг пачки из {len(chunk)} профилей отклонён Xray: "
                    f"{detail or 'без деталей'}",
                )
                tmp_path.unlink(missing_ok=True)
                log_path.unlink(missing_ok=True)
                return None

        launcher = self._launcher_or_default()
        try:
            proc = launcher.start(str(tmp_path), str(log_path))
        except Exception as e:  # noqa: BLE001
            self._last_start_error = f"xray start failed: {e}"
            tmp_path.unlink(missing_ok=True)
            log_path.unlink(missing_ok=True)
            return None

        with self._proc_lock:
            self._current_proc = proc

        if not self._wait_ready(proc, ports[0]):
            detail = _read_tail(log_path)
            self._stop(proc, tmp_path, log_path)
            self._last_start_error = (
                f"xray start failed: {detail}" if detail else "xray start failed"
            )
            add_log(
                "DEBUG",
                f"Check: Xray не поднялся для пачки из {len(chunk)} профилей — "
                f"{detail or 'лог пуст'}",
            )
            return None
        return proc, ports, tmp_path, log_path

    @staticmethod
    def _build_config(chunk, ports) -> dict:
        """Конфиг: http-inbound на каждый профиль + vless-outbound + правило маршрута."""
        inbounds = []
        outbounds = []
        rules = []
        for i, (_key, parsed) in enumerate(chunk):
            tag = f"node{i}"
            in_tag = f"in{i}"
            inbounds.append(
                {
                    "port": ports[i],
                    "listen": "127.0.0.1",
                    "protocol": "http",
                    "tag": in_tag,
                    "settings": {},
                }
            )
            outbounds.append(build_outbound(parsed, tag))
            rules.append(
                {"type": "field", "inboundTag": [in_tag], "outboundTag": tag}
            )
        return {
            # warning, а не none: если Xray не стартует, причина попадает в
            # лог-файл пачки и в last_error профиля — иначе диагностировать
            # «xray start failed» невозможно.
            "log": {"loglevel": "warning"},
            "inbounds": inbounds,
            "outbounds": outbounds,
            "routing": {"domainStrategy": "AsIs", "rules": rules},
        }

    def _wait_ready(self, proc, first_port: int) -> bool:
        """Ждёт, пока Xray начнёт принимать соединения на первом inbound пачки."""
        deadline = time.monotonic() + STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                return False
            try:
                with socket.create_connection(("127.0.0.1", first_port), timeout=0.25):
                    return True
            except OSError:
                time.sleep(0.025)
        return proc.poll() is None

    def _probe_chunk(self, chunk, ports, timeout, probe_stats, samples,
                     cancel, on_result, results, concurrency=None,
                     batch_limit=None) -> None:
        """Параллельные пробы пачки по локальным портам."""
        parallel = concurrency or len(chunk)
        parallel = max(1, min(parallel, len(chunk)))

        def run_one(key: int, port: int):
            if cancel and cancel.is_set():
                return key, None  # отмена: не пишем ложный «failed»
            if sys.is_finalizing():
                return key, {"ok": False, "latency": 0,
                             "error": "check interrupted by shutdown", "samples": 0}
            ok, lat, err, n = probe_median(
                port, timeout, self._probe_url_snapshot,
                samples, cancel, stats=probe_stats,
            )
            return key, {"ok": ok, "latency": lat, "error": err, "samples": n}

        def report(key, result):
            results[key] = result
            if on_result:
                try:
                    on_result(key, result)
                except Exception as e:  # noqa: BLE001 — прогресс не должен ронять прогон
                    add_log("DEBUG", f"Check result callback failed for #{key}: {e}")

        limit = float(batch_limit) if batch_limit else None
        futures: dict = {}
        pool = ThreadPoolExecutor(max_workers=parallel, thread_name_prefix="probe")
        finished: set = set()
        try:
            futures = {
                pool.submit(run_one, key, port): key
                for (key, _parsed), port in zip(chunk, ports)
            }
            for fut in as_completed(futures, timeout=limit):
                finished.add(fut)
                key = futures[fut]
                try:
                    _key, result = fut.result()
                except Exception as e:  # noqa: BLE001
                    result = {"ok": False, "latency": 0,
                              "error": f"probe crashed: {e}", "samples": 0}
                if result is None:
                    continue
                report(key, result)
        except FuturesTimeoutError:
            # Пачка «зависла»: сокеты/туннель не отвечают дольше расчётного
            # максимума. Помечаем застрявших timeout'ом и идём дальше — один
            # проблемный узел не должен останавливать весь прогон.
            stuck = [key for fut, key in futures.items() if fut not in finished]
            add_log(
                "WARN",
                f"Check: пачка не уложилась в {limit:.0f}с — {len(stuck)} профилей "
                "помечены «probe batch timeout», прогон продолжается",
            )
            for key in stuck:
                report(key, {"ok": False, "latency": 0,
                             "error": "probe batch timeout", "samples": 0})
        except RuntimeError as e:
            # «cannot schedule new futures after interpreter shutdown» —
            # панель останавливают прямо во время проверки. Это не ошибка
            # прогона: непроверенные профили остаются pending, а не failed.
            if "interpreter shutdown" in str(e).lower() or sys.is_finalizing():
                add_log("INFO", "Check interrupted by shutdown — профили остаются pending")
                return
            raise
        finally:
            # Не ждём застрявшие пробы: процесс Xray будет остановлен
            # вызывающим кодом, и их сокеты закроются сами.
            pool.shutdown(wait=False, cancel_futures=True)

    def _stop(self, proc, tmp_path, log_path) -> None:
        with self._proc_lock:
            if self._current_proc is proc:
                self._current_proc = None
        try:
            self._launcher_or_default().stop(proc)
        except Exception:
            pass
        for path in (tmp_path, log_path):
            if path:
                try:
                    Path(path).unlink(missing_ok=True)
                except Exception:
                    pass


def _read_tail(path: Path, limit: int = 300) -> str:
    """Последняя строка лога Xray — обычно там причина отказа старта."""
    try:
        text = Path(path).read_text(errors="replace").strip()
    except Exception:
        return ""
    if not text:
        return ""
    return text.splitlines()[-1][:limit]


# ─── Сборка outbound ───


def build_outbound(parsed: dict, tag: str) -> dict:
    """Строит vless-outbound из распарсенной ссылки (общий для панели и чекера)."""
    ob = {
        "protocol": "vless",
        "tag": tag,
        "settings": {
            "vnext": [
                {
                    "address": parsed["server"],
                    "port": parsed["port"],
                    "users": [{"id": parsed["uid"], "encryption": "none"}],
                }
            ]
        },
        "streamSettings": stream_settings(parsed),
    }
    flow = sanitize_flow(parsed.get("flow"))
    if flow:
        ob["settings"]["vnext"][0]["users"][0]["flow"] = flow
    return ob
