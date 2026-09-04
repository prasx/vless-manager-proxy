"""Управление прокси: поэтапное тестирование, фоновые задачи.

Бизнес-логика разделена на независимые стадии, которые выполняются строго
по очереди в рамках одного эксклюзивного «прогона» (глобальная блокировка):

    1. check  — проверка работоспособности всех профилей прогона (параллельно,
                до max_workers воркеров). Есть ответ от конфига (HTTP 2xx/3xx
                через временный Xray) — профиль помечается working, иначе failed.
    2. ping   — отдельный замер пинга для рабочих профилей: медиана из N проб
                через туннель (отдельный Xray на профиль), пишется в latency.
    3. speed  — замер скорости ТОЛЬКО по одному профилю за раз (строго
                последовательно): параллельные замеры скорости дают
                недостоверные данные, т.к. делят канал между собой.
                Длительность замера одного профиля задаётся в настройках
                (speed_test_min_sec — фиксированное окно).

Никакие два прогона/замера не могут выполняться одновременно: ручной тест
одного прокси, «Тест всех», фоновые цепочки и импорт+проверка сериализуются
общей блокировкой _run_lock. Это гарантирует достоверность замеров скорости.
"""

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .db import db_q, Settings
from .utils import add_log, now_utc, moscow_str, set_correlation_id
from .importer import import_from_url, import_from_txt
from .vless import parse_vless, stream_settings

# Сколько проб делает отдельный замер пинга (в latency идёт медиана)
PING_SAMPLES = 3

# Fallback-файлы для замера скорости (когда основной speed_test_url недоступен).
# Только достаточно крупные файлы: маленькие файлы дают недостоверный замер.
_SPEED_FALLBACK_URLS = (
    "http://speedtest.selectel.ru/10MB",
    "http://speedtest.tele2.net/10MB",
)


def _median(values):
    """Медиана списка чисел (пустой список → 0)."""
    if not values:
        return 0
    s = sorted(values)
    n = len(s)
    if n % 2:
        return s[n // 2]
    return int((s[n // 2 - 1] + s[n // 2]) / 2)


class ProxyManager:
    """Тестирование прокси, обновление статусов, фоновый циклический чекер."""

    def __init__(self):
        # Эксклюзивная блокировка прогона: только один замер за раз.
        self._run_lock = threading.Lock()
        self._last_run_db = 0.0
        self._last_run_import = 0.0
        self._shutdown = threading.Event()
        self._cancel = threading.Event()
        self._xray_children: dict[int, subprocess.Popen] = {}
        self._xray_children_lock = threading.Lock()
        self._check_stats = (0, 0)  # (ok, total) стадии check — для итоговой строки
        self._run_reasons: dict[str, int] = {}  # причины отказов текущего прогона
        self.progress = {
            "running": False,
            "label": "",
            "phase": "",            # import/check/ping/speed
            "stages": [],           # [{key,title,total,done,ok,status}]
            "total": 0, "done": 0, "ok": 0,   # счётчики ТЕКУЩЕЙ стадии
            "current": "",
            "cancel_requested": False,
            "last_completed": "",
            "last_label": "",
            "last_ok": 0,
            "last_total": 0,
            "started_at": 0.0,
        }
        self._progress_lock = threading.Lock()
        signal.signal(signal.SIGTERM, self._signal_handler)

    # ─── Общие ───

    @property
    def _vless_busy(self) -> bool:
        """Идёт ли сейчас какой-либо замер (эксклюзивный прогон)."""
        return self._run_lock.locked()

    def _signal_handler(self, signum, frame):
        add_log("INFO", "SIGTERM received, shutting down...")
        self.kill_all_xray_children()
        self._shutdown.set()
        sys.exit(0)

    def kill_all_xray_children(self):
        with self._xray_children_lock:
            for pid, proc in list(self._xray_children.items()):
                try:
                    os.killpg(pid, signal.SIGTERM)
                except Exception:
                    pass
            for pid, proc in list(self._xray_children.items()):
                try:
                    proc.wait(timeout=2)
                except Exception:
                    try:
                        os.killpg(pid, signal.SIGKILL)
                    except Exception:
                        pass
            self._xray_children.clear()

    @staticmethod
    def _free_port():
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    # ─── VLESS / ping helpers ───

    @staticmethod
    def _describe_probe_error(e) -> str:
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

    @staticmethod
    def _probe(http_port, timeout):
        """HTTP-проба через локальный HTTP-прокси (Xray уже запущен).
        Возвращает (ok, latency_ms, error).
        Даёт второй шанс, если первый отказ был подозрительно быстрым —
        такие отказы чаще всего транзиентные (blip сети, переиспользование соединения).
        """
        probe_url = Settings.probe_url()
        proxy_url = f"http://127.0.0.1:{http_port}"
        proxy_handler = urllib.request.ProxyHandler(
            {"http": proxy_url, "https": proxy_url}
        )
        opener = urllib.request.build_opener(proxy_handler)
        req_timeout = max(2, timeout - 1)
        retry_cutoff = max(0.9, req_timeout * 0.5)
        err = ""
        for attempt in (1, 2):
            req_start = time.time()
            try:
                resp = opener.open(probe_url, timeout=req_timeout)
                ok = resp.status < 400
                lat = int((time.time() - req_start) * 1000)
                return ok, lat, ""
            except Exception as e:
                err = ProxyManager._describe_probe_error(e)
                elapsed = time.time() - req_start
                if attempt == 1 and elapsed < retry_cutoff:
                    add_log(
                        "DEBUG",
                        f"Probe transient fail ({elapsed*1000:.0f}ms) — retrying: {err}",
                    )
                    continue
                add_log("DEBUG", f"Probe failed after {elapsed*1000:.0f}ms: {err}")
                return False, 0, err
        return False, 0, err

    # ─── Xray proxy helpers ───

    @staticmethod
    def _xray_config(parsed, http_port, socks_port):
        """Собирает конфиг Xray для одного прокси."""
        config = {
            "log": {"loglevel": "none"},
            "inbounds": [
                {
                    "port": socks_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"udp": True},
                    "tag": "socks-in",
                },
                {
                    "port": http_port,
                    "listen": "127.0.0.1",
                    "protocol": "http",
                    "settings": {},
                    "tag": "http-in",
                },
            ],
            "outbounds": [
                {
                    "protocol": "vless",
                    "tag": "proxy",
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
            ],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [
                    {
                        "type": "field",
                        "inboundTag": ["socks-in", "http-in"],
                        "outboundTag": "proxy",
                    }
                ],
            },
        }
        flow = parsed.get("flow")
        if flow:
            config["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"] = flow
        return config

    @staticmethod
    def _start_xray(parsed):
        """Запускает Xray для одного прокси.
        Возвращает (proc, tmp_path, http_port, error) или (None, None, None, error)."""
        xbin = Settings.xray_bin()
        if not Path(xbin).is_file():
            return None, None, None, f"xray binary not found: {xbin}"
        http_port = ProxyManager._free_port()
        socks_port = ProxyManager._free_port()
        config = ProxyManager._xray_config(parsed, http_port, socks_port)
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        with tmp:
            json.dump(config, tmp)
        tmp_path = tmp.name
        proc = None
        try:
            proc = subprocess.Popen(
                [xbin, "run", "-c", tmp_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            proxy_manager._track_xray(proc)
            retries = Settings.xray_startup_retries()
            for _ in range(retries):
                try:
                    s = socket.create_connection(("127.0.0.1", http_port), timeout=0.3)
                    s.close()
                    return proc, tmp_path, http_port, ""
                except (OSError, ConnectionRefusedError):
                    time.sleep(0.05)
        except Exception:
            pass
        ProxyManager._stop_xray(proc, tmp_path)
        return None, None, None, "xray start failed"

    @staticmethod
    def _stop_xray(proc, tmp_path):
        """Останавливает Xray и удаляет временный файл."""
        if proc:
            proxy_manager._untrack_xray(proc)
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except Exception:
                pass
            try:
                proc.wait(timeout=5)
            except Exception:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=3)
                except Exception:
                    pass
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    def _track_xray(self, proc):
        with self._xray_children_lock:
            self._xray_children[proc.pid] = proc

    def _untrack_xray(self, proc):
        with self._xray_children_lock:
            self._xray_children.pop(proc.pid, None)

    # ─── Прогресс прогона (с этапами) ───

    def progress_snapshot(self) -> dict:
        """Копия прогресса под блокировкой — для API/SSE."""
        with self._progress_lock:
            p = dict(self.progress)
            p["stages"] = [dict(s) for s in self.progress["stages"]]
            return p

    def _begin_run(self, label):
        """Начинает новый эксклюзивный прогон (владелец уже держит _run_lock)."""
        self._cancel.clear()
        self._run_reasons = {}
        with self._progress_lock:
            self.progress.update(
                running=True,
                label=label,
                phase="",
                stages=[],
                total=0, done=0, ok=0,
                current="",
                cancel_requested=False,
                started_at=time.time(),
            )

    def _set_current(self, text: str):
        """Безопасно обновляет строку «текущий объект» прогресса."""
        with self._progress_lock:
            self.progress["current"] = text

    def _begin_stage(self, key, title, total):
        """Переключает прогресс на новую стадию."""
        with self._progress_lock:
            self.progress["phase"] = key
            self.progress["total"] = total
            self.progress["done"] = 0
            self.progress["ok"] = 0
            self.progress["current"] = ""
            self.progress["stages"].append(
                {
                    "key": key,
                    "title": title,
                    "total": total,
                    "done": 0,
                    "ok": 0,
                    "status": "active",
                }
            )

    def _stage_advance(self, ok_item: bool, current_text: str = ""):
        """Инкремент прогресса текущей стадии на один обработанный профиль."""
        with self._progress_lock:
            p = self.progress
            p["done"] += 1
            if ok_item:
                p["ok"] += 1
            if current_text:
                p["current"] = current_text
            for st in p["stages"]:
                if st["status"] == "active":
                    st["done"] = p["done"]
                    st["ok"] = p["ok"]
                    break

    def _end_stage(self):
        """Завершает текущую стадию (done/сanceled/active→done)."""
        with self._progress_lock:
            p = self.progress
            for st in p["stages"]:
                if st["status"] == "active":
                    st["status"] = "canceled" if self._cancel.is_set() else "done"
                    st["done"] = st["total"]
                    break
            p["current"] = ""

    def _skip_stage(self, key, title):
        """Помечает стадию как пропущенную (нечего обрабатывать/отключена)."""
        with self._progress_lock:
            self.progress["stages"].append(
                {"key": key, "title": title, "total": 0, "done": 0, "ok": 0, "status": "skipped"}
            )

    def _finish_run(self, label):
        """Завершает прогон: фиксирует итоговую строку и сбрасывает активный прогресс."""
        ok_cnt, total_cnt = self._check_stats
        with self._progress_lock:
            p = self.progress
            p.update(
                running=False,
                phase="",
                total=0, done=0, ok=0,
                current="",
                cancel_requested=False,
                started_at=0.0,
            )
            if label:
                p["last_completed"] = moscow_str()
                p["last_label"] = label
                p["last_ok"] = ok_cnt
                p["last_total"] = total_cnt
            else:
                # Аварийное завершение без этапов — показываем как есть
                p["last_completed"] = moscow_str()

    def request_cancel(self):
        """Запросить отмену текущего прогона (безопасно из любого потока)."""
        self._cancel.set()
        with self._progress_lock:
            self.progress["cancel_requested"] = True

    # ─── Обновление статуса в БД ───

    @staticmethod
    def _update_vless_status(pid, ok, lat_vless, error=""):
        now = now_utc()
        err = (error or "").strip()[:200] or None
        if ok:
            db_q(
                "UPDATE proxies SET status='working', latency=?, latency_vless=?, failed_since=NULL, last_test_at=?, last_error=NULL WHERE id=?",
                (lat_vless, lat_vless, now, pid),
            )
        else:
            db_q(
                "UPDATE proxies SET status='failed', latency=0, latency_vless=0, speed_kbps=0, failed_since=COALESCE(failed_since, ?), last_test_at=?, last_error=? WHERE id=?",
                (now, now, err, pid),
            )

    @staticmethod
    def _reason_bucket(err) -> str:
        """Нормализует причину отказа для сводной статистики прогона."""
        err = (err or "").strip()
        if not err:
            return "unknown"
        if err.startswith("xray binary not found"):
            return "xray binary not found"
        return err[:60]

    # ─── Стадия 1: проверка работоспособности ───

    def _check_one(self, r, timeout):
        """Работоспособность одного профиля: ответ конфига есть → working.
        Скорость/пинг здесь НЕ меряются — это отдельные стадии."""
        if self._cancel.is_set():
            return r["id"], None
        parsed = parse_vless(r["link"])
        ok = False
        lat = 0
        err = ""
        if not parsed:
            err = "invalid link"
        else:
            proc, tmp_path, http_port, start_err = ProxyManager._start_xray(parsed)
            if proc:
                ok, lat, err = ProxyManager._probe(http_port, timeout)
                ProxyManager._stop_xray(proc, tmp_path)
            else:
                err = start_err or "xray start failed"
        self._update_vless_status(r["id"], ok, lat if ok else 0, err if not ok else "")
        if not ok:
            key = ProxyManager._reason_bucket(err)
            with self._progress_lock:
                self._run_reasons[key] = self._run_reasons.get(key, 0) + 1
        self._stage_advance(ok, current_text=f"#{r['id']}")
        return r["id"], ok

    def _stage_check(self, rows, timeout):
        """Стадия «Проверка работоспособности» — все профили параллельно.
        Возвращает (ok, total) по стадии."""
        ok_total = 0
        done_total = 0
        try:
            max_workers = Settings.max_workers()
            with ThreadPoolExecutor(max_workers=max_workers) as tpool:
                futures = {tpool.submit(self._check_one, r, timeout): r for r in rows}
                for f in as_completed(futures):
                    if self._cancel.is_set():
                        add_log("INFO", "Cancel requested, stopping check stage")
                        for ff in futures:
                            ff.cancel()
                        break
                    try:
                        _pid, ok = f.result()
                    except Exception as e:
                        add_log("ERROR", f"Check worker failed: {e}")
                        ok = False
                    done_total += 1
                    if ok:
                        ok_total += 1
            return ok_total, done_total
        except Exception as e:
            add_log("ERROR", f"Check stage crashed: {e}")
            return ok_total, done_total

    # ─── Стадия 2: замер пинга ───

    @staticmethod
    def _ping_one_proc(http_port, timeout, samples):
        """N проб через уже запущенный Xray. Возвращает список latency (ms)."""
        lats = []
        for _ in range(samples):
            if proxy_manager._cancel.is_set():
                break
            ok, lat, _err = ProxyManager._probe(http_port, timeout)
            if ok:
                lats.append(lat)
        return lats

    def _ping_one(self, r, timeout):
        """Замер пинга одного профиля: медиана из PING_SAMPLES проб."""
        if self._cancel.is_set():
            return r["id"], 0
        parsed = parse_vless(r["link"])
        if not parsed:
            return r["id"], 0
        proc, tmp_path, http_port, _err = ProxyManager._start_xray(parsed)
        med = 0
        if proc:
            try:
                lats = ProxyManager._ping_one_proc(http_port, timeout, PING_SAMPLES)
                med = _median(lats)
            finally:
                ProxyManager._stop_xray(proc, tmp_path)
        if med:
            # В latency/latency_vless идёт медиана — стабильный пинг
            db_q("UPDATE proxies SET latency=?, latency_vless=? WHERE id=?", (med, med, r["id"]))
        else:
            add_log("DEBUG", f"Ping #{r['id']}: all {PING_SAMPLES} probes failed (kept check latency)")
        self._stage_advance(med > 0, current_text=f"#{r['id']}")
        return r["id"], med

    def _stage_ping(self, working_rows, timeout):
        """Стадия «Замер пинга» — только рабочие профили, параллельно."""
        try:
            max_workers = Settings.max_workers()
            with ThreadPoolExecutor(max_workers=max_workers) as tpool:
                futures = {tpool.submit(self._ping_one, r, timeout): r for r in working_rows}
                for f in as_completed(futures):
                    if self._cancel.is_set():
                        for ff in futures:
                            ff.cancel()
                        break
                    try:
                        f.result()
                    except Exception as e:
                        add_log("ERROR", f"Ping worker failed: {e}")
        except Exception as e:
            add_log("ERROR", f"Ping stage crashed: {e}")

    # ─── Стадия 3: замер скорости (строго по одному) ───

    @staticmethod
    def _measure_url_kbps(http_port, url, window_sec, min_kbps, adaptive_sec):
        """Скачивает URL через HTTP-прокси ровно window_sec секунд, возвращает kbps.

        Окно замера фиксированное: файл может закончиться раньше — тогда он
        открывается заново, пока не наберётся время замера (или не наступит
        отмена/обрыв). Ранний выход возможен только при включённом пороге
        min_speed: если скорость уже уверенно выше порога — останавливаемся.
        """
        proxy_url = f"http://127.0.0.1:{http_port}"
        proxy_handler = urllib.request.ProxyHandler(
            {"http": proxy_url, "https": proxy_url}
        )
        opener = urllib.request.build_opener(proxy_handler)
        started = time.time()
        deadline = started + max(1, window_sec)
        total = 0
        req_timeout = min(max(window_sec + 2, 6), 45)
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            )
            resp = opener.open(req, timeout=req_timeout)
            while True:
                try:
                    buf = resp.read(131072)
                except Exception:
                    break  # поток оборвался — считаем то, что успели
                if not buf:
                    # Файл исчерпан раньше окна — качаем снова
                    if time.time() >= deadline:
                        break
                    try:
                        resp = opener.open(req, timeout=req_timeout)
                        continue
                    except Exception:
                        break
                total += len(buf)
                if time.time() >= deadline:
                    break
                # Adaptive early-exit: только при заданном пороге min_speed
                if min_kbps > 0:
                    elapsed = time.time() - started
                    if elapsed >= max(1, adaptive_sec) and elapsed > 0:
                        cur = int((total * 8) / (elapsed * 1000))
                        if cur >= min_kbps * 1.3:
                            return cur
        except Exception:
            pass
        elapsed = time.time() - started
        if total <= 0 or elapsed <= 0:
            return 0
        return int((total * 8) / (elapsed * 1000))

    @classmethod
    def _measure_kbps(cls, http_port, window_sec):
        """Замер скорости через HTTP-прокси с фиксированным окном window_sec.
        Пробует основной speed_test_url, затем крупные fallback-файлы."""
        window_sec = max(1, int(window_sec))
        primary = Settings.get("speed_test_url", "").strip()
        urls = []
        if primary:
            urls.append(primary)
        for u in _SPEED_FALLBACK_URLS:
            if u not in urls:
                urls.append(u)
        min_kbps = Settings.min_speed_kbps()
        adaptive_sec = Settings.speed_test_adaptive_sec()
        for url in urls:
            kbps = cls._measure_url_kbps(http_port, url, window_sec, min_kbps, adaptive_sec)
            if kbps:
                return kbps
        return 0

    def _stage_speed(self, speed_rows):
        """Стадия «Замер скорости» — СТРОГО по одному профилю за раз.
        Параллельные замеры скорости дают недостоверные данные (делят канал)."""
        window_sec = Settings.speed_test_duration_sec()
        for r in speed_rows:
            if self._cancel.is_set():
                add_log("INFO", "Cancel requested, stopping speed stage")
                break
            parsed = parse_vless(r["link"])
            host = r.get("host") or (parsed.get("server") if parsed else f"#{r['id']}")
            if not parsed:
                self._stage_advance(False, current_text=f"#{r['id']} {host}: invalid link")
                continue
            proc, tmp_path, http_port, _err = ProxyManager._start_xray(parsed)
            if not proc:
                self._stage_advance(False, current_text=f"#{r['id']} {host}: xray start failed")
                continue
            try:
                self._set_current(f"#{r['id']} {host} — замер {window_sec}с…")
                kbps = ProxyManager._measure_kbps(http_port, window_sec)
                if kbps:
                    db_q("UPDATE proxies SET speed_kbps=? WHERE id=?", (kbps, r["id"]))
                    add_log("INFO", f"Speed #{r['id']} ({host}): {kbps}kbps / {window_sec}s window")
                else:
                    add_log("WARN", f"Speed #{r['id']} ({host}): no data in {window_sec}s window")
                self._stage_advance(kbps > 0,
                                    current_text=f"#{r['id']} {host}: {kbps}kbps" if kbps else f"#{r['id']} {host}: 0 kbps")
            finally:
                ProxyManager._stop_xray(proc, tmp_path)

    # ─── Конвейер прогона ───

    def _execute_pipeline(self, rows, label, *, apply_config=False, apply_blocking=False,
                          cleanup_failed=False, import_srcs=None, enrich_after_check=False,
                          rows_after_import=False):
        """Выполняет поэтапный конвейер. Владелец УЖЕ держит _run_lock.

        import_srcs: list[dict] источников для стадии импорта (опционально,
        только для Import+Check) — каждый источник: {'id','type','url','name'}.
        rows_after_import: True — профили для проверки выбираются из БД уже
        ПОСЛЕ стадии импорта (чтобы тестировать свежеимпортированные).
        Возвращает (ok, total) стадии check.
        """
        cid = uuid.uuid4().hex[:12]
        set_correlation_id(cid)
        self._begin_run(label)
        self._check_stats = (0, 0)
        try:
            # ── Стадия 0 (опционально): импорт источников ──
            if import_srcs:
                self._begin_stage("import", "Импорт источников", len(import_srcs))
                try:
                    for src in import_srcs:
                        if self._cancel.is_set():
                            break
                        src_label = src.get("name") or src.get("url") or f"#{src['id']}"
                        self._set_current(f"источник: {src_label}")
                        try:
                            if src.get("type") == "txt":
                                import_from_txt(src["id"])
                            else:
                                import_from_url(src.get("url", ""), source_id=src["id"])
                            db_q("UPDATE sources SET last_import=? WHERE id=?",
                                 (now_utc(), src["id"]))
                        except RuntimeError as e:
                            add_log("ERROR", f"Import source #{src['id']} failed: {e}")
                        self._stage_advance(True, current_text=f"источник: {src_label}")
                finally:
                    self._end_stage()
                if self._cancel.is_set():
                    self._finish_run(label)
                    return self._check_stats

            if rows_after_import:
                rows = db_q("SELECT id, link, host FROM proxies")
            if rows:
                rows = [dict(r) for r in rows]

            # ── Стадия 1: проверка работоспособности ──
            timeout = Settings.vless_per_proxy_timeout()
            if not rows:
                self._skip_stage("check", "Проверка работоспособности")
            else:
                self._begin_stage("check", "Проверка работоспособности", len(rows))
                add_log("INFO", f"Check stage ({label}): {len(rows)} proxies")
                ok_cnt, done_cnt = self._stage_check(rows, timeout)
                self._check_stats = (ok_cnt, done_cnt)
                self._end_stage()
                parts = self._reason_summary()
                summary = f"{label}: ok {ok_cnt}/{done_cnt}"
                if parts:
                    summary += " · не работают: " + ", ".join(parts)
                add_log("INFO", f"Check done · {summary} · {moscow_str()}")
                if enrich_after_check:
                    from .utils import enrich_all_unknown_countries
                    enrich_all_unknown_countries()
                if self._cancel.is_set():
                    self._finish_run(label)
                    return self._check_stats

            # ── Стадия 2: пинг рабочих профилей прогона ──
            row_ids = [r["id"] for r in rows if r.get("id")]
            working = self._working_rows(row_ids) if row_ids else []
            if working:
                self._begin_stage("ping", "Замер пинга", len(working))
                add_log("INFO", f"Ping stage ({label}): {len(working)} working proxies (median of {PING_SAMPLES})")
                self._stage_ping(working, timeout)
                self._end_stage()
                if self._cancel.is_set():
                    self._finish_run(label)
                    return self._check_stats
            else:
                self._skip_stage("ping", "Замер пинга")

            # ── Стадия 3: скорость — строго по одному профилю ──
            if self._speed_enabled_for(working):
                speed_rows = self._speed_rows(row_ids)
                if speed_rows:
                    self._begin_stage("speed", "Замер скорости", len(speed_rows))
                    add_log("INFO", f"Speed stage ({label}): {len(speed_rows)} proxies, ONE AT A TIME, "
                                    f"{Settings.speed_test_duration_sec()}s each")
                    self._stage_speed(speed_rows)
                    self._end_stage()
                else:
                    self._skip_stage("speed", "Замер скорости")
            else:
                self._skip_stage("speed", "Замер скорости")

            # ── Пост-обработка ──
            if cleanup_failed and not self._cancel.is_set():
                deleted = db_q("SELECT COUNT(*) c FROM proxies WHERE status='failed'")[0]["c"]
                if deleted:
                    db_q("DELETE FROM proxies WHERE status='failed'")
                    add_log("INFO", f"Auto-cleanup: deleted {deleted} failed proxies")

            if apply_config and not self._cancel.is_set():
                from .xray_configurator import xray_configurator
                xray_configurator.apply_all(blocking=apply_blocking)
                add_log("INFO", f"Config applied after {label}")

            self._finish_run(label)
            return self._check_stats
        except Exception as e:
            add_log("ERROR", f"Pipeline {label} crashed: {e}")
            self._finish_run(label)
            return self._check_stats

    def _speed_enabled_for(self, working) -> bool:
        if Settings.get("speed_test_enabled", "true") != "true":
            return False
        if int(Settings.get("speed_test_max", "15")) <= 0:
            return False
        if not working:
            return False
        return True

    def _working_rows(self, row_ids):
        if not row_ids:
            return []
        placeholders = ",".join("?" * len(row_ids))
        return [
            dict(r)
            for r in db_q(
                f"SELECT id, link, host FROM proxies WHERE id IN ({placeholders}) AND status='working' ORDER BY latency_vless ASC, id ASC",
                row_ids,
            )
        ]

    def _speed_rows(self, row_ids):
        """Топ-N рабочих профилей прогона по пингу для замера скорости."""
        speed_max = int(Settings.get("speed_test_max", "15"))
        if speed_max <= 0:
            return []
        placeholders = ",".join("?" * len(row_ids))
        return [
            dict(r)
            for r in db_q(
                f"SELECT id, link, host FROM proxies WHERE id IN ({placeholders}) AND status='working' AND latency_vless > 0 ORDER BY latency_vless ASC, id ASC LIMIT ?",
                row_ids + [speed_max],
            )
        ]

    def _reason_summary(self):
        """Сводка причин отказов ТЕКУЩЕГО прогона (из стадии check)."""
        reasons = sorted(self._run_reasons.items(), key=lambda kv: (-kv[1], kv[0]))
        parts = [f"{k}: {v}" for k, v in reasons[:6]]
        if len(reasons) > 6:
            parts.append(f"прочие: {sum(v for _, v in reasons[6:])}")
        return parts

    # ─── Точки входа ───

    def start_test_all(self) -> bool:
        """Запускает полный конвейер для всех прокси (в фоне).
        True — запущен, False — уже идёт другой замер или нет прокси."""
        rows = db_q("SELECT id, link, host FROM proxies")
        if not rows:
            add_log("WARN", "Test all: no proxies to test")
            return False
        return self._start_background(rows, "all", apply_config=True, apply_blocking=True)

    def start_batch_test(self, rows, label="batch-test") -> bool:
        """Запускает конвейер для выбранных прокси (в фоне)."""
        rows = [dict(r) for r in rows]
        if not rows:
            return False
        return self._start_background(rows, label, apply_config=True, apply_blocking=True)

    def start_retest_failed(self) -> bool:
        """Конвейер только для failed-прокси (в фоне)."""
        rows = db_q("SELECT id, link, host FROM proxies WHERE status='failed' ORDER BY id ASC")
        if not rows:
            add_log("INFO", "Retest failed: no failed proxies")
            return False
        return self._start_background(rows, "retest-failed", apply_config=True, apply_blocking=True)

    def _start_background(self, rows, label, *, apply_config, apply_blocking=False) -> bool:
        """Захватывает эксклюзивную блокировку здесь, а исполняет конвейер
        в отдельном потоке (блокировку освобождает поток по завершении)."""
        if not self._run_lock.acquire(blocking=False):
            add_log("WARN", f"Another test is already running, ignoring {label}")
            return False

        def worker():
            try:
                self._execute_pipeline(
                    rows, label,
                    apply_config=apply_config,
                    apply_blocking=apply_blocking,
                )
            except Exception as e:
                add_log("ERROR", f"Pipeline {label} crashed: {e}")
            finally:
                try:
                    self._run_lock.release()
                except RuntimeError:
                    pass

        t = threading.Thread(target=worker, daemon=True, name=f"pipeline-{label}")
        t.start()
        return True

    def measure_single(self, pid: int) -> dict:
        """Полный конвейер для ОДНОГО прокси (синхронно, эксклюзивно).
        Возвращает {busy:True} если идёт другой замер, иначе результат."""
        rows = db_q("SELECT id, link, host FROM proxies WHERE id=?", (pid,))
        if not rows:
            return {"busy": False, "error": "not found"}
        row = rows[0]
        if not self._run_lock.acquire(blocking=False):
            add_log("WARN", f"Another test is running — single test #{pid} skipped")
            return {"busy": True}
        try:
            self._execute_pipeline([row], "single", apply_config=False)
            after = db_q(
                "SELECT status, latency, latency_vless, speed_kbps, last_error FROM proxies WHERE id=?",
                (pid,),
            )
            if not after:
                return {"busy": False, "error": "deleted during test"}
            r = after[0]
            return {
                "busy": False,
                "status": r["status"],
                "latency": r["latency_vless"] or 0,
                "speed": r["speed_kbps"] or 0,
                "error": r["last_error"] or (None if r["status"] == "working" else "test failed"),
            }
        finally:
            try:
                self._run_lock.release()
            except RuntimeError:
                pass

    def test_and_update_vless(self, link):
        """Одиночный тест по ссылке (используется после /api/add).
        Если идёт другой замер — пропускается (не создаём параллельные замеры)."""
        parsed = parse_vless(link)
        if not parsed:
            return
        rows = db_q("SELECT id, link, host FROM proxies WHERE link=?", (link,))
        if not rows:
            return
        pid = rows[0]["id"]
        res = self.measure_single(pid)
        if res.get("busy"):
            add_log("WARN", f"Add-test #{pid} skipped: another measurement in progress")
        else:
            detail = f" ({res.get('latency')}ms, {res.get('speed')}kbps)" if res.get("status") == "working" else ""
            add_log("INFO", f"Add-test #{pid} -> {res.get('status')}{detail}")

    # ─── Фоновые цепочки ───

    def background_checker(self):
        """Фоновый цикл: два независимых таймера с приоритетом.
        import+check имеет приоритет над db-only. Не запускаются одновременно."""
        while not self._shutdown.is_set():
            if self._shutdown.wait(timeout=30):
                break
            try:
                if self._vless_busy:
                    continue
                now = time.time()
                due_import = now - self._last_run_import >= Settings.check_interval_import()
                due_db = now - self._last_run_db >= Settings.check_interval_db()

                if due_import:
                    self._last_run_import = now
                    threading.Thread(target=self._run_import_chain, daemon=True).start()
                elif due_db:
                    self._last_run_db = now
                    threading.Thread(target=self._run_db_chain, daemon=True).start()
            except Exception as e:
                add_log("ERROR", f"Background checker crashed: {e}")

    def failover_checker(self):
        """Лёгкий фоновый поток: проверяет каждые 30 сек,
        все ли ожидаемые node* outbound'ы живы в Xray.
        Если часть нод пропала — инициирует apply_all() для пересборки конфига."""
        add_log("INFO", "Failover checker started (interval: 30s)")
        while not self._shutdown.is_set():
            if self._shutdown.wait(timeout=30):
                break
            try:
                from .xray_configurator import xray_configurator

                if not xray_configurator.api_ok():
                    continue

                # Пока идёт тест, статусы в БД ещё меняются: если пересобирать
                # конфиг в этот момент, получим ложный рассинхрон (напр. 4/23)
                # и лишние рестарты Xray каждые 30 сек.
                if self._vless_busy:
                    continue

                max_active = Settings.max_active_proxies()
                blocked = Settings.blocked_countries()
                codes = [c.strip() for c in blocked.split(",") if c.strip()] if blocked else []
                if codes:
                    placeholders = ",".join("?" * len(codes))
                    working_count = db_q(
                        f"SELECT COUNT(*) c FROM proxies WHERE status='working' AND latency_vless > 0 AND country NOT IN ({placeholders})",
                        codes,
                    )[0]["c"]
                else:
                    working_count = db_q(
                        "SELECT COUNT(*) c FROM proxies WHERE status='working' AND latency_vless > 0"
                    )[0]["c"]
                expected = min(working_count, max_active)

                active = xray_configurator._active_node_count()
                if active < expected:
                    add_log(
                        "WARN",
                        f"Failover: only {active}/{expected} node outbounds active — triggering rebuild",
                    )
                    xray_configurator.apply_all(blocking=False)
            except Exception as e:
                add_log("ERROR", f"Failover checker crashed: {e}")

    def _run_import_chain(self):
        """Импорт из источников → поэтапный конвейер → сборка конфига.
        Вся цепочка держит эксклюзивную блокировку: импорт и замер не
        перемешиваются с ручными тестами."""
        if not self._run_lock.acquire(blocking=False):
            add_log("WARN", "Import+check skipped: another measurement in progress")
            return
        try:
            src_list = [
                dict(r)
                for r in db_q(
                    "SELECT s.id, s.type, s.url, COALESCE(s.name, 'source') AS name FROM sources s"
                )
            ]
            self._execute_pipeline(
                [],
                "import+check",
                import_srcs=src_list,
                rows_after_import=True,
                enrich_after_check=True,
                apply_config=Settings.get("apply_after_test", "true") == "true",
            )
            # import+check протестировал все прокси — db-check не нужен
            self._last_run_db = time.time()
            add_log("INFO", "Import+check cycle completed")
        except Exception as e:
            add_log("ERROR", f"Import+check cycle crashed: {e}")
        finally:
            try:
                self._run_lock.release()
            except RuntimeError:
                pass

    def _run_db_chain(self):
        """Проверка прокси из БД (без импорта) → сборка конфига."""
        if not self._run_lock.acquire(blocking=False):
            add_log("WARN", "DB check skipped: another measurement in progress")
            return
        try:
            rows = db_q("SELECT id, link, host FROM proxies")
            self._execute_pipeline(
                rows,
                "db-check",
                enrich_after_check=True,
                apply_config=Settings.get("apply_after_test", "true") == "true",
                cleanup_failed=Settings.get("db_check_auto_cleanup", "false") == "true",
            )
            add_log("INFO", "DB check cycle completed")
        except Exception as e:
            add_log("ERROR", f"DB check cycle crashed: {e}")
        finally:
            try:
                self._run_lock.release()
            except RuntimeError:
                pass


proxy_manager = ProxyManager()
