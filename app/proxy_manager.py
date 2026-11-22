"""Управление прокси: поэтапное тестирование, фоновые задачи.

Бизнес-логика разделена на независимые стадии, которые выполняются строго
по очереди в рамках одного эксклюзивного «прогона» (глобальная блокировка):

    1. check  — проверка работоспособности профилей. Один процесс Xray
                обслуживает пачку профилей (см. app/checker.py), поэтому
                прогон упирается в сеть, а не в запуск процессов. Пока туннель
                жив, сразу снимается медиана из нескольких проб — отдельная
                стадия пинга с новым запуском Xray больше не нужна.
    2. speed  — замер скорости ТОЛЬКО по одному профилю за раз (строго
                последовательно): параллельные замеры скорости дают
                недостоверные данные, т.к. делят канал между собой.
                Длительность замера одного профиля задаётся в настройках
                (speed_test_min_sec), у стадии есть общий бюджет времени.

Никакие два прогона/замера не могут выполняться одновременно: ручной тест
одного прокси, «Тест всех», фоновые цепочки и импорт+проверка сериализуются
общей блокировкой _run_lock. Это гарантирует достоверность замеров скорости.

Поддержание рабочих профилей:
    * рабочий профиль перепроверяется в каждом прогоне (next_test_at = NULL);
    * упавший получает паузу, растущую с числом падений подряд
      (15 мин → 1 ч → 3 ч → 12 ч), и не тратит на себя прогон каждый раз;
    * автоудаление (если включено) трогает только профили, упавшие трижды
      подряд, а не все failed после одного неудачного прогона.
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
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

from . import importer
from .checker import (
    BatchXrayChecker,
    PortReserver,
    build_outbound,
    tcp_reachable,
    validate_link,
)
from .db import Settings, db_q
from .importer import import_sources, save_source_status
from .utils import (
    add_log,
    moscow_str,
    now_utc,
    schedule_country_enrichment,
    set_correlation_id,
)
from .vless import parse_vless

# Пауза перед следующей проверкой упавшего профиля по числу падений подряд.
FAIL_BACKOFF_SEC = (900, 3600, 10800, 43200)  # 15 мин, 1 ч, 3 ч, 12 ч

# Fallback-файлы для замера скорости (когда основной speed_test_url недоступен).
# Только достаточно крупные файлы и глобально доступные CDN-хосты:
# российские зеркала (selectel/tele2) недоступны с иностранных exit-нод.
_SPEED_FALLBACK_URLS = (
    "https://speed.cloudflare.com/__down?bytes=10000000",
    "http://cachefly.cachefly.net/100mb.test",
    "https://proof.ovh.net/files/100Mb.dat",
)


def _backoff_seconds(fail_count: int) -> int:
    """Пауза до следующей проверки для профиля, упавшего fail_count раз подряд."""
    idx = max(0, min(fail_count - 1, len(FAIL_BACKOFF_SEC) - 1))
    return FAIL_BACKOFF_SEC[idx]


class ProxyManager:
    """Тестирование прокси, обновление статусов, фоновый циклический чекер."""

    def __init__(self, checker: BatchXrayChecker | None = None):
        # Эксклюзивная блокировка прогона: только один замер за раз.
        self._run_lock = threading.Lock()
        self._last_run_db = 0.0
        self._last_run_import = 0.0
        self._shutdown = threading.Event()
        self._cancel = threading.Event()
        self._xray_children: dict[int, subprocess.Popen] = {}
        self._xray_children_lock = threading.Lock()
        self._ports = PortReserver()
        self._checker = checker or BatchXrayChecker(port_reserver=self._ports)
        self._check_stats = (0, 0)  # (ok, total) стадии check — для итоговой строки
        self._run_reasons: dict[str, int] = {}  # причины отказов текущего прогона
        # Какой URL замера скорости сработал в этом прогоне (см. _measure_kbps).
        self._speed_url: str = ""
        # Сколько раз URL замера не дал данных в этом прогоне (см. _speed_urls).
        self._speed_failed: dict[str, int] = {}
        self.progress = {
            "running": False,
            "label": "",
            "phase": "",            # import/check/speed
            "stages": [],           # [{key,title,total,done,ok,status,seconds}]
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
        try:
            self._checker.kill_current()
        except Exception:
            pass
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

    # ─── Xray для одного прокси (замер скорости, одиночный тест) ───

    def _xray_config(self, parsed, http_port):
        """Собирает минимальный конфиг Xray для одного прокси (http-inbound)."""
        return {
            "log": {"loglevel": "none"},
            "inbounds": [
                {
                    "port": http_port,
                    "listen": "127.0.0.1",
                    "protocol": "http",
                    "settings": {},
                    "tag": "http-in",
                }
            ],
            "outbounds": [build_outbound(parsed, "proxy")],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [
                    {"type": "field", "inboundTag": ["http-in"], "outboundTag": "proxy"}
                ],
            },
        }

    def _start_xray(self, parsed):
        """Запускает Xray для одного прокси.
        Возвращает (proc, tmp_path, http_port, error) или (None, None, None, error)."""
        xbin = Settings.xray_bin()
        if not Path(xbin).is_file():
            return None, None, None, f"xray binary not found: {xbin}"
        last_err = "xray start failed"
        for _attempt in range(2):
            ports = self._ports.reserve(1)
            if not ports:
                return None, None, None, "no free local ports"
            http_port = ports[0]
            config = self._xray_config(parsed, http_port)
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
                self._track_xray(proc)
                if self._wait_port(proc, http_port):
                    return proc, tmp_path, http_port, ""
                last_err = "xray start failed"
            except Exception as e:  # noqa: BLE001
                last_err = f"xray start failed: {e}"
            self._stop_xray(proc, tmp_path)
        return None, None, None, last_err

    @staticmethod
    def _wait_port(proc, port) -> bool:
        """Ждёт готовности порта Xray. Учитывает xray_startup_retries (шаг 50 мс)."""
        retries = Settings.xray_startup_retries()
        deadline = time.monotonic() + max(1.0, retries * 0.05)
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                return False
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                    return True
            except OSError:
                time.sleep(0.05)
        return False

    def _stop_xray(self, proc, tmp_path):
        """Останавливает Xray и удаляет временный файл."""
        if proc:
            self._untrack_xray(proc)
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
            p["stages"] = [
                {k: v for k, v in s.items() if not k.startswith("_")}
                for s in self.progress["stages"]
            ]
            return p

    def _begin_run(self, label):
        """Начинает новый эксклюзивный прогон (владелец уже держит _run_lock)."""
        self._cancel.clear()
        self._run_reasons = {}
        self._speed_url = ""
        self._speed_failed = {}
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
                    "seconds": 0,
                    "_started": time.monotonic(),
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
        """Завершает текущую стадию (done/canceled/active→done)."""
        with self._progress_lock:
            p = self.progress
            for st in p["stages"]:
                if st["status"] == "active":
                    st["status"] = "canceled" if self._cancel.is_set() else "done"
                    st["done"] = st["total"]
                    started = st.pop("_started", None)
                    if started:
                        st["seconds"] = int(time.monotonic() - started)
                    break
            p["current"] = ""

    def _skip_stage(self, key, title):
        """Помечает стадию как пропущенную (нечего обрабатывать/отключена)."""
        with self._progress_lock:
            self.progress["stages"].append(
                {"key": key, "title": title, "total": 0, "done": 0, "ok": 0,
                 "status": "skipped", "seconds": 0}
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
            p["last_completed"] = moscow_str()
            if label:
                p["last_label"] = label
                p["last_ok"] = ok_cnt
                p["last_total"] = total_cnt

    def request_cancel(self):
        """Запросить отмену текущего прогона (безопасно из любого потока)."""
        self._cancel.set()
        with self._progress_lock:
            self.progress["cancel_requested"] = True

    # ─── Обновление статуса в БД ───

    @staticmethod
    def _update_vless_status(pid, ok, lat_vless, error=""):
        """Пишет результат проверки: успех сбрасывает backoff, отказ — наращивает."""
        now = now_utc()
        err = (error or "").strip()[:200] or None
        if ok:
            db_q(
                "UPDATE proxies SET status='working', latency=?, latency_vless=?, "
                "failed_since=NULL, fail_count=0, next_test_at=NULL, last_ok_at=?, "
                "last_test_at=?, last_error=NULL WHERE id=?",
                (lat_vless, lat_vless, now, now, pid),
            )
            return
        row = db_q("SELECT COALESCE(fail_count, 0) AS fc FROM proxies WHERE id=?", (pid,))
        fail_count = (row[0]["fc"] if row else 0) + 1
        next_at = None
        if Settings.failed_backoff():
            next_at = now + timedelta(seconds=_backoff_seconds(fail_count))
        db_q(
            "UPDATE proxies SET status='failed', latency=0, latency_vless=0, "
            "speed_kbps=0, failed_since=COALESCE(failed_since, ?), last_test_at=?, "
            "last_error=?, fail_count=?, next_test_at=? WHERE id=?",
            (now, now, err, fail_count, next_at, pid),
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

    def _record_result(self, pid, ok, lat, err):
        """Пишет результат одного профиля и двигает прогресс стадии."""
        self._update_vless_status(pid, ok, lat if ok else 0, "" if ok else err)
        if not ok:
            key = self._reason_bucket(err)
            with self._progress_lock:
                self._run_reasons[key] = self._run_reasons.get(key, 0) + 1
        self._stage_advance(ok, current_text=f"#{pid}")

    # ─── Стадия 1: проверка работоспособности (+ медиана пинга) ───

    def _stage_check(self, rows, timeout):
        """Стадия «Проверка работоспособности».

        Возвращает (ok, total). Внутри: быстрый разбор ссылок, TCP-префильтр
        и батч-проверка одним процессом Xray на пачку.
        """
        ok_total = 0
        done_total = 0

        def handle(key, ok, lat=0, err=""):
            nonlocal ok_total, done_total
            self._record_result(key, ok, lat, err)
            done_total += 1
            if ok:
                ok_total += 1

        # 1. Разбор и структурная валидация: битые ссылки не оправляют батч в Xray.
        items: list[tuple[int, dict]] = []
        for r in rows:
            if self._cancel.is_set():
                break
            parsed = parse_vless(r["link"])
            bad = validate_link(parsed)
            if bad:
                handle(r["id"], False, 0, bad)
            else:
                items.append((r["id"], parsed))

        if self._cancel.is_set():
            return ok_total, done_total

        # 2. TCP-префильтр: мёртвый server:port отсекается за 1–2 с без Xray.
        if Settings.tcp_prefilter() and items:
            items = self._tcp_prefilter(items, handle)
        if not items or self._cancel.is_set():
            return ok_total, done_total

        # 3. Батч-проверка: один Xray на пачку, пробы параллельно.
        batch_size = Settings.check_batch_size()
        samples = Settings.ping_samples()
        add_log(
            "DEBUG",
            f"Check: {len(items)} после TCP-префильтра, батчи по {batch_size}, "
            f"таймаут {timeout:.1f}с, медиана из {samples} проб",
        )

        def on_result(key, result):
            handle(key, result["ok"], result["latency"], result["error"])

        try:
            self._checker.check(
                items,
                timeout=timeout,
                batch_size=batch_size,
                cancel=self._cancel,
                on_result=on_result,
                start_concurrency=batch_size,
            )
        except Exception as e:  # noqa: BLE001
            add_log("ERROR", f"Check stage crashed: {e}")
        return ok_total, done_total

    def _tcp_prefilter(self, items, handle):
        """Отсекает заведомо недоступные server:port. Возвращает выживших."""
        timeout = Settings.tcp_prefilter_timeout()
        parallel = max(1, min(Settings.check_batch_size(), len(items)))

        def check_one(item):
            key, parsed = item
            ok, err = tcp_reachable(parsed["server"], parsed["port"], timeout)
            return key, parsed, ok, err

        survivors = []
        with ThreadPoolExecutor(max_workers=parallel, thread_name_prefix="tcp") as pool:
            for key, parsed, ok, err in pool.map(check_one, items):
                if self._cancel.is_set():
                    break
                if ok:
                    survivors.append((key, parsed))
                else:
                    handle(key, False, 0, err)
        return survivors

    # ─── Стадия 2: замер скорости (строго по одному) ───

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

    def _speed_urls(self) -> list[str]:
        """Кандидаты URL замера: рабочий из этого прогона — первым.

        Если какой-то URL уже дважды не дал данных в этом прогоне, он уходит
        в конец: чаще всего он просто недоступен с exit-нод, и заставлять
        каждый следующий профиль выжидать на нём полное окно бессмысленно.
        """
        primary = Settings.get("speed_test_url", "").strip()
        candidates: list[str] = []
        if self._speed_url:
            candidates.append(self._speed_url)
        if primary and primary not in candidates:
            candidates.append(primary)
        for u in _SPEED_FALLBACK_URLS:
            if u not in candidates:
                candidates.append(u)
        healthy = [
            u for u in candidates
            if u == self._speed_url or self._speed_failed.get(u, 0) < 2
        ]
        return healthy or candidates

    def _measure_kbps(self, http_port, window_sec):
        """Замер скорости через HTTP-прокси с фиксированным окном window_sec.

        URL, с которого в этом прогоне уже качалось, пробуется первым: раньше
        недоступный основной URL заставлял каждый профиль выжидать полное окно
        на нём, прежде чем перейти к рабочему CDN.
        """
        window_sec = max(1, int(window_sec))
        min_kbps = Settings.min_speed_kbps()
        adaptive_sec = Settings.speed_test_adaptive_sec()
        for url in self._speed_urls():
            kbps = self._measure_url_kbps(http_port, url, window_sec, min_kbps, adaptive_sec)
            if kbps:
                self._speed_url = url
                self._speed_failed.pop(url, None)
                return kbps
            self._speed_failed[url] = self._speed_failed.get(url, 0) + 1
        return 0

    def _stage_speed(self, speed_rows):
        """Стадия «Замер скорости» — СТРОГО по одному профилю за раз.
        Параллельные замеры скорости дают недостоверные данные (делят канал)."""
        window_sec = Settings.speed_test_duration_sec()
        budget = Settings.speed_stage_budget_sec()
        deadline = time.monotonic() + budget if budget else 0.0
        measured = 0
        for r in speed_rows:
            if self._cancel.is_set():
                add_log("INFO", "Cancel requested, stopping speed stage")
                break
            if deadline and time.monotonic() > deadline:
                add_log(
                    "WARN",
                    f"Speed stage: бюджет {budget}с исчерпан — {measured} замеров, "
                    f"остальные профили пропущены",
                )
                break
            parsed = parse_vless(r["link"])
            host = r.get("host") or (parsed.get("server") if parsed else f"#{r['id']}")
            if not parsed:
                self._stage_advance(False, current_text=f"#{r['id']} {host}: invalid link")
                continue
            proc, tmp_path, http_port, _err = self._start_xray(parsed)
            if not proc:
                self._stage_advance(False, current_text=f"#{r['id']} {host}: xray start failed")
                continue
            try:
                self._set_current(f"#{r['id']} {host} — замер {window_sec}с…")
                kbps = self._measure_kbps(http_port, window_sec)
                if kbps:
                    measured += 1
                    db_q("UPDATE proxies SET speed_kbps=? WHERE id=?", (kbps, r["id"]))
                    add_log("INFO", f"Speed #{r['id']} ({host}): {kbps}kbps / {window_sec}s window")
                else:
                    add_log("WARN", f"Speed #{r['id']} ({host}): no data in {window_sec}s window")
                self._stage_advance(kbps > 0,
                                    current_text=f"#{r['id']} {host}: {kbps}kbps" if kbps else f"#{r['id']} {host}: 0 kbps")
            finally:
                self._stop_xray(proc, tmp_path)
        if speed_rows and measured == 0:
            add_log(
                "WARN",
                f"Speed stage: 0/{len(speed_rows)} measurements succeeded — "
                f"проверьте speed_test_url ({Settings.get('speed_test_url')}) "
                f"и доступность CDN с exit-нод",
            )

    # ─── Конвейер прогона ───

    def _execute_pipeline(self, rows, label, *, apply_config=False, apply_blocking=False,
                          cleanup_failed=False, import_srcs=None, enrich_after_check=False,
                          rows_after_import=False, timeout=None):
        """Выполняет поэтапный конвейер. Владелец УЖЕ держит _run_lock.

        import_srcs: list[dict] источников для стадии импорта (опционально,
        только для Import+Check) — каждый источник: {'id','type','url','name'}.
        rows_after_import: True — профили для проверки выбираются из БД уже
        ПОСЛЕ стадии импорта (чтобы тестировать свежеимпортированные).
        timeout: таймаут пробы. По умолчанию — probe_timeout (быстрая проверка),
        для ручного теста одного прокси передаётся vless_per_proxy_timeout.
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
                advanced: set = set()

                def on_import_result(res):
                    """Прогресс стадии: один опрошенный источник — один шаг."""
                    advanced.add(res.get("id"))
                    label_ = res.get("name") or f"#{res.get('id')}"
                    self._stage_advance(
                        res.get("status") in importer.REACHED_STATUSES,
                        current_text=f"источник: {label_} ({res.get('status_label') or res['status']})",
                    )

                try:
                    report = import_sources(
                        import_srcs,
                        on_result=on_import_result,
                        should_stop=self._cancel.is_set,
                    )
                    for res in report["results"]:
                        save_source_status(res)
                        if res.get("id") not in advanced:
                            # Пропущенные предохранителем или бюджетом — тоже шаг
                            # стадии: без этого прогресс стоит и закрывается скачком.
                            label_ = res.get("name") or f"#{res.get('id')}"
                            self._stage_advance(
                                False,
                                current_text=f"источник: {label_} (пропущен)",
                            )
                    self._set_current("")
                finally:
                    self._end_stage()
                if self._cancel.is_set():
                    self._finish_run(label)
                    return self._check_stats

            if rows_after_import:
                rows = self._due_rows()
            if rows:
                rows = [dict(r) for r in rows]

            # ── Стадия 1: проверка работоспособности (+ медиана пинга) ──
            timeout = float(timeout if timeout is not None else Settings.probe_timeout())
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
                    schedule_country_enrichment()
                if self._cancel.is_set():
                    self._finish_run(label)
                    return self._check_stats

            # ── Стадия 2: скорость — строго по одному профилю ──
            row_ids = [r["id"] for r in rows if r.get("id")]
            working = self._working_rows(row_ids) if row_ids else []
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
                self._cleanup_failed()

            if apply_config and not self._cancel.is_set():
                from .xray_configurator import xray_configurator
                xray_configurator.apply_all(blocking=apply_blocking)
                add_log("INFO", f"Config applied after {label}")

            self._finish_run(label)
            return self._check_stats
        except Exception as e:  # noqa: BLE001
            add_log("ERROR", f"Pipeline {label} crashed: {e}")
            self._finish_run(label)
            return self._check_stats

    def _cleanup_failed(self):
        """Автоудаление только тех профилей, что упали несколько раз подряд."""
        deleted = db_q(
            "SELECT COUNT(*) c FROM proxies WHERE status='failed' AND COALESCE(fail_count, 0) >= 3"
        )[0]["c"]
        if deleted:
            db_q(
                "DELETE FROM proxies WHERE status='failed' AND COALESCE(fail_count, 0) >= 3"
            )
            add_log("INFO", f"Auto-cleanup: deleted {deleted} failed proxies (3+ fails)")

    def _speed_enabled_for(self, working) -> bool:
        if Settings.get("speed_test_enabled", "true") != "true":
            return False
        if int(Settings.get("speed_test_max", "8")) <= 0:
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
        speed_max = int(Settings.get("speed_test_max", "8"))
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

    def _due_rows(self):
        """Профили, которым пора на проверку (упавшие ждут своей паузы)."""
        now = now_utc()
        return db_q(
            "SELECT id, link, host FROM proxies "
            "WHERE next_test_at IS NULL OR next_test_at <= ? ORDER BY id ASC",
            (now,),
        )

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
        rows = db_q("SELECT id, link, host FROM proxies ORDER BY id ASC")
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
            except Exception as e:  # noqa: BLE001
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
            self._execute_pipeline(
                [row], "single", apply_config=False,
                timeout=float(Settings.vless_per_proxy_timeout()),
            )
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
            except Exception as e:  # noqa: BLE001
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
                # Считаем ожидаемые ноды тем же селектором, что и генератор
                # конфига (учитывает blocked_countries, порог скорости и
                # fallback при отсутствии замеров) — иначе ложный рассинхрон
                # и пересборка конфига каждые 30 секунд.
                expected = len(xray_configurator._proxy_link_rows(max_active))

                active = xray_configurator._active_node_count()
                if active < expected:
                    add_log(
                        "WARN",
                        f"Failover: only {active}/{expected} node outbounds active — triggering rebuild",
                    )
                    xray_configurator.apply_all(blocking=False)
            except Exception as e:  # noqa: BLE001
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
        except Exception as e:  # noqa: BLE001
            add_log("ERROR", f"Import+check cycle crashed: {e}")
        finally:
            try:
                self._run_lock.release()
            except RuntimeError:
                pass

    def _run_db_chain(self):
        """Проверка прокси из БД (без импорта) → сборка конфига.

        Берутся только профили, которым пора по backoff: при 1500 профилях
        из которых 1490 мёртвых, прогон не тратит на них время каждый раз.
        """
        rows = self._due_rows()
        if not rows:
            add_log("INFO", "DB check: нет профилей, которым пора на проверку — пропуск")
            self._last_run_db = time.time()
            return
        if not self._run_lock.acquire(blocking=False):
            add_log("WARN", "DB check skipped: another measurement in progress")
            return
        try:
            self._execute_pipeline(
                [dict(r) for r in rows],
                "db-check",
                enrich_after_check=True,
                apply_config=Settings.get("apply_after_test", "true") == "true",
                cleanup_failed=Settings.get("db_check_auto_cleanup", "false") == "true",
            )
            add_log("INFO", "DB check cycle completed")
        except Exception as e:  # noqa: BLE001
            add_log("ERROR", f"DB check cycle crashed: {e}")
        finally:
            try:
                self._run_lock.release()
            except RuntimeError:
                pass


proxy_manager = ProxyManager()
