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
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .db import Settings
from .utils import add_log
from .vless import sanitize_flow, stream_settings

# Сколько ждать, пока Xray поднимет все inbounds пачки, секунд.
STARTUP_TIMEOUT = 6.0

# Диапазон локальных портов для inbounds батч-чекера.
PORT_RANGE_START = 20000
PORT_RANGE_END = 40000

# Транспорты, которые умеет собирать stream_settings().
KNOWN_NETWORKS = frozenset(
    {"tcp", "ws", "grpc", "kcp", "h2", "http", "xhttp", "quic", "splithttp"}
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


def probe_once(http_port: int, timeout: float, probe_url: str) -> tuple[bool, int, str, float]:
    """Одна HTTP-проба через локальный http-inbound.

    Возвращает (ok, latency_ms, error, elapsed_sec).
    """
    req_timeout = max(1.0, timeout)
    started = time.time()
    try:
        resp = _opener_for_port(http_port).open(probe_url, timeout=req_timeout)
        ok = resp.status < 400
        try:
            resp.close()
        except Exception:
            pass
        # Не меньше 1 мс: latency_vless > 0 — условие попадания в конфиг,
        # а округление быстрого ответа до 0 исключило бы живой профиль.
        latency_ms = max(1, int((time.time() - started) * 1000))
        return ok, latency_ms, "", time.time() - started
    except Exception as e:  # noqa: BLE001 — нужна человекочитаемая причина
        return False, 0, describe_probe_error(e), time.time() - started


def probe_median(
    http_port: int,
    timeout: float,
    probe_url: str,
    samples: int = 3,
    cancel: threading.Event | None = None,
) -> tuple[bool, int, str, int]:
    """Проверка профиля: первая проба решает «жив/мёртв», затем ещё пробы для медианы.

    Возвращает (ok, latency_ms, error, samples_ok). Медиана пишется в latency —
    так стадия пинга больше не нужна отдельным проходом с новым процессом Xray.
    """
    ok, lat, err, elapsed = probe_once(http_port, timeout, probe_url)
    if not ok and elapsed < max(0.4, timeout * 0.5) and not (cancel and cancel.is_set()):
        # Быстрый отказ чаще всего транзиентный (blip сети) — один повтор.
        ok, lat, err, _ = probe_once(http_port, timeout, probe_url)
    if not ok:
        return False, 0, err, 0
    lats = [lat]
    for _ in range(max(0, samples - 1)):
        if cancel and cancel.is_set():
            break
        ok2, lat2, _err2, _ = probe_once(http_port, timeout, probe_url)
        if ok2:
            lats.append(lat2)
    return True, _median(lats), "", len(lats)


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
    net = (parsed.get("type") or "tcp").lower()
    if net not in KNOWN_NETWORKS:
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
    ) -> dict[int, dict]:
        """Проверяет профили, возвращает {id: {ok, latency, error, samples}}.

        items — список (id, parsed). batch_size — сколько профилей в одном
        процессе Xray; они же проверяются параллельно. on_result(key, result)
        вызывается по мере готовности (прогресс и запись в БД).
        """
        results: dict[int, dict] = {}
        if not items:
            return results
        batch_size = max(1, int(batch_size or Settings.check_batch_size()))
        timeout = max(1.0, float(timeout))
        probe_url = Settings.probe_url()
        samples = Settings.ping_samples()

        for start in range(0, len(items), batch_size):
            if cancel and cancel.is_set():
                break
            chunk = items[start:start + batch_size]
            self._check_chunk(
                chunk, timeout, probe_url, samples, cancel, on_result, results,
                concurrency=start_concurrency,
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

    def _check_chunk(self, chunk, timeout, probe_url, samples, cancel,
                     on_result, results, concurrency=None) -> None:
        """Проверяет одну пачку; при отказе старта делит её пополам."""
        if cancel and cancel.is_set():
            return
        started = self._start_chunk(chunk)
        if started is None:
            if len(chunk) > 1:
                mid = len(chunk) // 2
                self._check_chunk(chunk[:mid], timeout, probe_url, samples,
                                  cancel, on_result, results, concurrency)
                if cancel and cancel.is_set():
                    return
                self._check_chunk(chunk[mid:], timeout, probe_url, samples,
                                  cancel, on_result, results, concurrency)
            else:
                key, _parsed = chunk[0]
                result = {"ok": False, "latency": 0,
                          "error": self._last_start_error or "xray start failed", "samples": 0}
                results[key] = result
                if on_result:
                    try:
                        on_result(key, result)
                    except Exception as e:  # noqa: BLE001
                        add_log("DEBUG", f"Check result callback failed for #{key}: {e}")
            return
        proc, ports, tmp_path, log_path = started
        if cancel and cancel.is_set():
            # Отмена: профили пачки остаются непроверенными (не «failed»).
            self._stop(proc, tmp_path, log_path)
            return
        try:
            self._probe_chunk(chunk, ports, timeout, probe_url, samples,
                              cancel, on_result, results, concurrency)
        finally:
            self._stop(proc, tmp_path, log_path)

    _last_start_error: str = ""

    def _start_chunk(self, chunk):
        """Запускает Xray для пачки. Возвращает (proc, ports, tmp_path, log_path) или None."""
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
            "log": {"loglevel": "none"},
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

    def _probe_chunk(self, chunk, ports, timeout, probe_url, samples,
                     cancel, on_result, results, concurrency=None) -> None:
        """Параллельные пробы пачки по локальным портам."""
        parallel = concurrency or len(chunk)
        parallel = max(1, min(parallel, len(chunk)))

        def run_one(key: int, port: int):
            if cancel and cancel.is_set():
                return key, None  # отмена: не пишем ложный «failed»
            ok, lat, err, n = probe_median(port, timeout, probe_url, samples, cancel)
            return key, {"ok": ok, "latency": lat, "error": err, "samples": n}

        def report(key, result):
            results[key] = result
            if on_result:
                try:
                    on_result(key, result)
                except Exception as e:  # noqa: BLE001 — прогресс не должен ронять прогон
                    add_log("DEBUG", f"Check result callback failed for #{key}: {e}")

        with ThreadPoolExecutor(max_workers=parallel, thread_name_prefix="probe") as pool:
            futures = {
                pool.submit(run_one, key, port): key
                for (key, _parsed), port in zip(chunk, ports)
            }
            for fut in as_completed(futures):
                key = futures[fut]
                try:
                    _key, result = fut.result()
                except Exception as e:  # noqa: BLE001
                    result = {"ok": False, "latency": 0,
                              "error": f"probe crashed: {e}", "samples": 0}
                if result is None:
                    continue
                report(key, result)

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
