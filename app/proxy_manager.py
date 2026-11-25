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
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from ipaddress import ip_address
from pathlib import Path

from . import importer, netcheck
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

# Пауза между «промежуточными» применениями конфига во время замера скорости.
# Замер идёт по одному профилю; между профилями дешевле применить новые данные,
# чтобы рабочие узлы появлялись в конфиге и подписке, не дожидаясь конца стадии.
INCREMENTAL_APPLY_SEC = 20.0

# Fallback-файлы для замера скорости (когда основной speed_test_url недоступен).
# Основной каталог живёт в app/netcheck.py; здесь — запасные, чтобы стадия
# скорости не осталась без данных, если пользователь задал один мёртвый URL.
_SPEED_FALLBACK_URLS = tuple(netcheck.SPEED_URL_CANDIDATES[1:])


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
        # Когда failover последний раз сам инициировал пересборку: защита от
        # цикла «пересборка каждые 30 сек».
        self._last_failover_apply = 0.0
        # Какой URL замера скорости сработал в этом прогоне (см. _measure_kbps).
        self._speed_url: str = ""
        # Сколько раз URL замера не дал данных в этом прогоне (см. _speed_urls).
        self._speed_failed: dict[str, int] = {}
        # Причина отказа каждого URL замера за прогон: логируем один раз на URL,
        # чтобы понять, почему «замеры недоступны» (TLS, CONNECT, 403, DNS…).
        self._speed_error_reasons: dict[str, str] = {}
        # Файл лога текущего скоростного Xray (для причины отказа в логе).
        self._last_speed_log: str = ""
        # Причина отказа последнего замера (для ручного теста одного профиля).
        self._last_speed_xray_tail: str = ""
        # URL для ручного теста скорости одного профиля (перекрывает настройку).
        self._speed_url_override: str = ""
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
            # warning: если exit-нода не отдала ответ, в логе Xray будет причина
            # («failed to read response from host: …») — она попадает в panel-лог.
            "log": {"loglevel": "warning"},
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
            # Лог Xray (warning) в файл: если замер не получился, в нём будет
            # причина («failed to read response from host: connection reset»),
            # а не только «no data». stdout+stderr — в один файл.
            log = tempfile.NamedTemporaryFile(
                mode="w", suffix=".log", delete=False, prefix="xray-speed-"
            )
            log_path = log.name
            proc = None
            try:
                proc = subprocess.Popen(
                    [xbin, "run", "-c", tmp_path],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                self._track_xray(proc)
                self._last_speed_log = log_path
                if self._wait_port(proc, http_port):
                    return proc, tmp_path, http_port, ""
                last_err = "xray start failed"
            except Exception as e:  # noqa: BLE001
                last_err = f"xray start failed: {e}"
            finally:
                log.close()
            self._stop_xray(proc, tmp_path)
            try:
                os.unlink(log_path)
            except Exception:
                pass
        return None, None, None, last_err

    def _speed_log_tail(self, limit: int = 220) -> str:
        """Последняя строка лога скоростного Xray — причина отказа."""
        path = getattr(self, "_last_speed_log", "") or ""
        if not path:
            return ""
        try:
            text = Path(path).read_text(errors="replace").strip()
        except Exception:
            return ""
        lines = [ln for ln in text.splitlines() if ln.strip()]
        return lines[-1][:limit] if lines else ""

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
        log_path = getattr(self, "_last_speed_log", "") or ""
        if log_path:
            try:
                os.unlink(log_path)
            except Exception:
                pass
            self._last_speed_log = ""

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
        self._speed_error_reasons = {}
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
        try:
            # Оценка источников должна отражать только что полученные результаты.
            from .source_quality import invalidate as _invalidate_quality

            _invalidate_quality()
        except Exception:
            pass
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
            "speed_kbps=0, speed_max_kbps=0, failed_since=COALESCE(failed_since, ?), "
            "last_test_at=?, last_error=?, fail_count=?, next_test_at=? WHERE id=?",
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

        # 0. Перед прогоном проверяем сам URL проверки: если он мёртв из панели
        #    или давно не тестировался — подбираем лучший из каталога. Это
        #    дешёвая страховка от «все профили мёртвые» из-за одного URL.
        probe_urls = netcheck.probe_url_candidates()
        if Settings.probe_url_auto():
            try:
                current = netcheck.ensure_probe_url(timeout=min(6, max(2, timeout)))
                probe_urls = netcheck.probe_url_candidates()
                if current and current not in probe_urls:
                    probe_urls.insert(0, current)
            except Exception as e:  # noqa: BLE001 — подбор URL не должен ронять прогон
                add_log("DEBUG", f"Probe URL pre-check failed: {e}")

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
            def prefilter_progress(done, total):
                self._set_current(f"TCP {done}/{total}")
                if done % 500 == 0 or done == total:
                    add_log("DEBUG", f"TCP-префильтр: {done}/{total}")

            items = self._tcp_prefilter(items, handle, on_progress=prefilter_progress)
        if not items or self._cancel.is_set():
            return ok_total, done_total

        # 3. Батч-проверка: один Xray на пачку, пробы параллельно.
        batch_size = Settings.check_batch_size()
        samples = Settings.ping_samples()
        add_log(
            "DEBUG",
            f"Check: {len(items)} после TCP-префильтра, батчи по {batch_size}, "
            f"таймаут {timeout:.1f}с, повторов {Settings.probe_retries()}, "
            f"медиана из {samples} проб, URL пробы: {', '.join(probe_urls[:3])}",
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
                probe_urls=probe_urls,
            )
        except Exception as e:  # noqa: BLE001
            add_log("ERROR", f"Check stage crashed: {e}")
        self._log_probe_url_result(probe_urls)
        return ok_total, done_total

    def _log_probe_url_result(self, probe_urls) -> None:
        """Пишет, какой URL проверки реально отвечал, и переключает на лучший.

        «Тест лучших ссылок для остальных проверок»: если основной URL ни разу
        не ответил через туннели, а другой кандидат ответил — запоминаем его в
        настройках, и следующие прогоны (и observatory Xray) идут через него.
        """
        stats = getattr(self._checker, "last_probe_stats", None)
        if stats is None or stats.total() < 10:
            return
        best = stats.best()
        primary = probe_urls[0] if probe_urls else Settings.probe_url()
        summary = stats.summary()
        if summary:
            add_log("INFO", f"URL проверки: {summary}")
        # Запоминаем URL, доказавший работу через туннели: прямая проверка из
        # панели не должна перебивать его на следующем прогоне. Приоритет —
        # текущий URL настроек, если он отвечал.
        if stats.ok_count(primary):
            netcheck.remember_tunnel_verified_url(primary)
        elif best:
            netcheck.remember_tunnel_verified_url(best)
        if best and best != primary and stats.ok_count(primary) == 0:
            try:
                Settings.set("probe_url", best)
                # Фиксируем выбор как «недавно проверенный»: иначе следующий
                # прогон снова уйдёт в прямой тест из панели и может вернуть URL,
                # который через туннели не отвечает.
                netcheck.remember_probe_url_test(
                    [{"url": best, "ok": True, "status": 204, "ms": 0, "error": ""}]
                )
            except Exception as e:  # noqa: BLE001
                add_log("DEBUG", f"Could not switch probe_url: {e}")
                return
            add_log(
                "WARN",
                f"URL проверки {primary} не ответил ни разу за {stats.total()} проб — "
                f"переключён на {best}. Следующие проверки пойдут через него.",
            )

    def _tcp_prefilter(self, items, handle, on_progress=None):
        """Отсекает заведомо недоступные server:port. Возвращает выживших.

        Медленные и защищённые серверы не всегда отвечают на SYN с первого
        раза: после таймаута/недоступности делаем ещё попытку с увеличенным
        таймаутом. Раньше такие узлы выпадали как «tcp timeout», не доходя до
        проверки через Xray — именно поэтому часть живых профилей не попадала
        в замер скорости.

        Доменные имена не проверяем здесь: getaddrinfo не ограничивается
        socket-timeout и при медленном DNS блокирует воркер на десятки секунд.
        На 8000+ профилях это и давало «0/8245» на несколько минут. Домены
        идут в Xray, который сам решает DNS; TCP-префильтр остаётся быстрым
        для IP-литералов.
        """
        timeout = Settings.tcp_prefilter_timeout()
        retries = Settings.tcp_prefilter_retries()
        parallel = max(1, min(Settings.tcp_prefilter_workers(), len(items)))
        total = len(items)
        checked = 0
        domains = 0
        add_log(
            "DEBUG",
            f"TCP-префильтр: {len(items)} адресов, {parallel} параллельно, "
            f"таймаут {timeout:.1f}с, повторов {retries}",
        )

        def is_ip(host: str) -> bool:
            try:
                ip_address((host or "").strip().strip("[]"))
                return True
            except ValueError:
                return False

        def check_one(item):
            key, parsed = item
            host = parsed.get("server") or ""
            if not is_ip(host):
                # DNS-резолв — не дело быстрого TCP-префильтра.
                return key, parsed, True, "", True
            ok, err = tcp_reachable(host, parsed["port"], timeout)
            attempt = 0
            while (
                not ok
                and err in ("tcp timeout", "tcp unreachable")
                and attempt < retries
            ):
                attempt += 1
                # Последующие попытки терпеливее: SYN/retransmit у защищённых
                # узлов может занимать несколько секунд.
                ok, err = tcp_reachable(
                    host, parsed["port"], timeout * (1 + attempt)
                )
            return key, parsed, ok, err, False

        survivors = []
        with ThreadPoolExecutor(max_workers=parallel, thread_name_prefix="tcp") as pool:
            for key, parsed, ok, err, skipped in pool.map(check_one, items):
                checked += 1
                if skipped:
                    domains += 1
                if self._cancel.is_set():
                    break
                if ok:
                    survivors.append((key, parsed))
                else:
                    handle(key, False, 0, err)
                if on_progress and (checked % 25 == 0 or checked == total):
                    on_progress(checked, total)
        if domains:
            add_log(
                "DEBUG",
                f"TCP-префильтр: {domains} доменных имён пропущено "
                "(их разрешит Xray, а не медленный системный DNS)",
            )
        return survivors

    # ─── Стадия 2: замер скорости (строго по одному) ───

    @staticmethod
    def _measure_url_kbps(http_port, url, window_sec, min_kbps, adaptive_sec,
                          extra_headers=None):
        """Скачивает URL через HTTP-прокси ровно window_sec секунд.

        Возвращает (средняя_kbps, максимальная_kbps, ошибка). Средняя — за всё
        окно, максимальная — лучшие 0.5 секунды: именно она показывает, сколько
        канал реально отдаёт на пике, а не размазанное среднее. Ошибка
        заполняется, если запрос вообще не удался — по ней видно, почему замер
        недоступен (TLS, CONNECT, 403, DNS и т.п.), а не только «no data».

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
        peak = 0
        sample_t = started
        sample_total = 0
        req_timeout = min(max(window_sec + 2, 6), 45)
        error = ""

        def take_sample(now: float) -> None:
            """Фиксирует пик по последнему окну 0.5 с (мелкие окна — шум)."""
            nonlocal peak, sample_t, sample_total
            dt = now - sample_t
            if dt < 0.5:
                return
            delta = total - sample_total
            if delta > 0:
                inst = int((delta * 8) / (dt * 1000))
                peak = max(peak, inst)
            sample_t = now
            sample_total = total

        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            if extra_headers:
                headers.update(extra_headers)
            req = urllib.request.Request(url, headers=headers)
            resp = opener.open(req, timeout=req_timeout)
            while True:
                try:
                    buf = resp.read(131072)
                except Exception as e:  # noqa: BLE001
                    error = error or f"обрыв чтения: {type(e).__name__}: {e}"
                    break  # поток оборвался — считаем то, что успели
                if not buf:
                    # Файл исчерпан раньше окна — качаем снова
                    if time.time() >= deadline:
                        break
                    try:
                        resp = opener.open(req, timeout=req_timeout)
                        continue
                    except Exception as e:  # noqa: BLE001
                        error = error or f"переоткрытие: {type(e).__name__}: {e}"
                        break
                total += len(buf)
                now = time.time()
                take_sample(now)
                if now >= deadline:
                    break
                # Adaptive early-exit: только при заданном пороге min_speed
                if min_kbps > 0:
                    elapsed = now - started
                    if elapsed >= max(1, adaptive_sec) and elapsed > 0:
                        cur = int((total * 8) / (elapsed * 1000))
                        if cur >= min_kbps * 1.3:
                            peak = max(peak, cur)
                            return cur, peak, ""
        except urllib.error.HTTPError as e:  # noqa: PERF203
            # Xray HTTP-inbound отвечает 503 с текстом причины, если не смог
            # открыть соединение к цели. Этот текст — главная улика, почему
            # файл замера «недоступен с exit-нод».
            body = ""
            try:
                body = e.read(300).decode("utf-8", "replace").strip()
            except Exception:
                pass
            error = f"HTTP {e.code}: {body or e.reason}"[:300]
        except Exception as e:  # noqa: BLE001 — причина нужна в логе, а не только «0»
            error = f"{type(e).__name__}: {e}"
        elapsed = time.time() - started
        if total <= 0 or elapsed <= 0:
            return 0, 0, error or "0 байт за окно"
        # Последние неполные 0.5 с тоже могут быть пиком.
        take_sample(time.time())
        avg = int((total * 8) / (elapsed * 1000))
        return avg, max(peak, avg), ""

    def _speed_urls(self) -> list[str]:
        """Кандидаты URL замера: рабочий из этого прогона — первым.

        Основной URL идёт из настроек, затем каталог app/netcheck.py и запасные
        CDN. Если какой-то URL уже дважды не дал данных в этом прогоне, он
        уходит в конец: чаще всего он просто недоступен с exit-нод, и заставлять
        каждый следующий профиль выжидать на нём полное окно бессмысленно.
        """
        candidates: list[str] = []
        if self._speed_url_override:
            candidates.append(self._speed_url_override)
        if self._speed_url:
            candidates.append(self._speed_url)
        for u in netcheck.speed_url_candidates() + list(_SPEED_FALLBACK_URLS):
            if u and u not in candidates:
                candidates.append(u)
        healthy = [
            u for u in candidates
            if u in (self._speed_url_override, self._speed_url)
            or self._speed_failed.get(u, 0) < 2
        ]
        result = healthy or candidates

        def rank(u: str) -> int:
            if u in (self._speed_url_override, self._speed_url):
                return 0
            # HTTP-файлы раньше HTTPS: у многих exit-нод TLS режется, и
            # HTTPS-попытки впустую съедают бюджет профиля.
            return 1 if u.startswith("http://") else 2

        return sorted(result, key=rank)

    @staticmethod
    def _ip_endpoint(url: str):
        """Параметры запроса к файлу по IP с исходным Host.

        У exit-нод DNS часто «отравлен»: домен резолвится в заглушку. Резолвим
        домен на сервере панели и обращаемся к IP, а исходный домен передаём
        в заголовке Host (через CONNECT-туннель, чтобы Xray не подменил Host
        на IP).
        """
        try:
            parts = urllib.parse.urlsplit(url)
        except Exception:  # noqa: BLE001
            return None
        host = parts.hostname
        if parts.scheme != "http" or not host:
            return None
        try:
            ip = socket.gethostbyname(host)
        except Exception:  # noqa: BLE001
            return None
        if not ip or ip == host:
            return None
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        return {
            "ip": ip,
            "host": host,
            "port": parts.port or 80,
            "path": path,
        }

    @staticmethod
    def _measure_connect_kbps(http_port, endpoint, window_sec, min_kbps, adaptive_sec):
        """Замер через CONNECT-туннель с корректным Host (обход DNS exit-ноды).

        Обычный HTTP-прокси Xray подменяет заголовок Host на IP из URL, поэтому
        виртуальные хосты ломаются. Здесь соединение открывается CONNECT'ом до
        IP, а HTTP-запрос с настоящим Host шлём уже внутри туннеля.
        """
        window_sec = max(1, int(window_sec))
        ip = endpoint["ip"]
        host = endpoint["host"]
        port = int(endpoint["port"])
        path = endpoint["path"]
        started = time.time()
        deadline = started + window_sec
        total = 0
        sample_t = started
        sample_total = 0
        peak = 0
        req_timeout = min(max(window_sec + 3, 8), 45)
        sock = None
        error = ""
        try:
            sock = socket.create_connection(("127.0.0.1", http_port), timeout=req_timeout)
            sock.settimeout(req_timeout)

            def read_headers() -> bytes:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = sock.recv(4096)
                    if not chunk:
                        raise OSError("пустой ответ")
                    data += chunk
                    if len(data) > 65536:
                        raise OSError("слишком длинные заголовки")
                return data

            sock.sendall(
                f"CONNECT {ip}:{port} HTTP/1.1\r\nHost: {ip}:{port}\r\n\r\n".encode()
            )
            header = read_headers()
            status_line = header.split(b"\r\n", 1)[0].decode("utf-8", "replace")
            if " 200" not in status_line:
                return 0, 0, f"CONNECT: {status_line[:100]}"
            sock.sendall(
                (
                    f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                    "Accept: */*\r\nConnection: close\r\n\r\n"
                ).encode()
            )
            data = read_headers()
            head, _, rest = data.partition(b"\r\n\r\n")
            status_line = head.split(b"\r\n", 1)[0].decode("utf-8", "replace")
            if " 200" not in status_line:
                return 0, 0, f"HTTP: {status_line[:100]}"
            total += len(rest)
            # total == 0 — тело могло прийти следующим пакетом чуть позже окна:
            # делаем хотя бы одну попытку чтения (recv ограничен таймаутом).
            while time.time() < deadline or total == 0:
                try:
                    chunk = sock.recv(65536)
                except OSError as e:
                    error = f"обрыв чтения: {type(e).__name__}: {e}"
                    break
                if not chunk:
                    break
                total += len(chunk)
                now = time.time()
                dt = now - sample_t
                if dt >= 0.5:
                    delta = total - sample_total
                    if delta > 0:
                        peak = max(peak, int((delta * 8) / (dt * 1000)))
                    sample_t, sample_total = now, total
                if min_kbps > 0 and now - started >= max(1, adaptive_sec):
                    cur = int((total * 8) / ((now - started) * 1000))
                    if cur >= min_kbps * 1.3:
                        peak = max(peak, cur)
                        return cur, peak, ""
        except Exception as e:  # noqa: BLE001
            error = f"{type(e).__name__}: {e}"
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        elapsed = time.time() - started
        if total <= 0 or elapsed <= 0:
            return 0, 0, error or "0 байт за окно"
        avg = int((total * 8) / (elapsed * 1000))
        return avg, max(peak, avg), ""

    def _measure_kbps(self, http_port, window_sec):
        """Замер скорости через HTTP-прокси.

        Возвращает (средняя_kbps, максимальная_kbps). URL, с которого в этом
        прогоне уже качалось, пробуется первым: раньше недоступный основной URL
        заставлял каждый профиль выжидать полное окно на нём, прежде чем
        перейти к рабочему CDN. Причину отказа каждого URL запоминаем один раз
        за прогон — по ней в логе видно, почему «замеры скорости недоступны».
        """
        window_sec = max(1, int(window_sec))
        min_kbps = Settings.min_speed_kbps()
        adaptive_sec = Settings.speed_test_adaptive_sec()
        # Бюджет на ОДИН профиль: если exit-нода молча дропает соединения, то
        # перебор всех URL по 10-12 с даёт 70–100 с на профиль, и стадия
        # успевает проверить 5 узлов вместо 50. Ограничиваем перебор.
        profile_started = time.monotonic()
        profile_budget = max(12.0, min(45.0, window_sec * 2 + 10))
        tls_fail = 0
        egress_fail = 0
        for url in self._speed_urls():
            if time.monotonic() - profile_started > profile_budget:
                add_log(
                    "DEBUG",
                    f"Speed: бюджет {profile_budget:.0f}с на профиль исчерпан — "
                    "остальные URL не пробую",
                )
                break
            if tls_fail >= 2 and url.startswith("https://"):
                # Два разных HTTPS-файла оборвались на TLS — не тратим бюджет
                # на остальные https у этой exit-ноды.
                continue
            avg, peak, error = self._measure_url_kbps(
                http_port, url, window_sec, min_kbps, adaptive_sec
            )
            if avg:
                self._speed_url = url
                self._speed_failed.pop(url, None)
                self._speed_error_reasons.pop(url, None)
                return avg, peak
            if "SSL" in error or "TLS" in error:
                tls_fail += 1
            # Домен не открылся — пробуем тот же файл по IP через CONNECT-туннель
            # (обход подмены DNS у exit-ноды; Host передаём настоящий).
            if time.monotonic() - profile_started <= profile_budget:
                endpoint = self._ip_endpoint(url)
                if endpoint:
                    add_log(
                        "DEBUG",
                        f"Speed: {url.split('/')[2] if '://' in url else url} не открылся "
                        f"напрямую ({error[:100]}); пробую по IP {endpoint['ip']} "
                        f"с Host: {endpoint['host']}",
                    )
                    avg2, peak2, error2 = self._measure_connect_kbps(
                        http_port, endpoint, window_sec, min_kbps, adaptive_sec
                    )
                    if avg2:
                        add_log(
                            "INFO",
                            f"Speed: файл замера доступен с этой exit-ноды только "
                            f"по IP (DNS домена не резолвится/подменяется): "
                            f"{url.split('/')[2]}",
                        )
                        self._speed_url = url
                        self._speed_failed.pop(url, None)
                        self._speed_error_reasons.pop(url, None)
                        return avg2, peak2
                    add_log("DEBUG", f"Speed: по IP тоже не вышло — {error2[:160]}")
                    error = error2 or error
                    # Пустой ответ/сброс после CONNECT может быть свойством
                    # конкретного файла/хоста. Раньше после первого такого URL
                    # цикл обрывался, и Cloudflare/Google вообще не проверялись.
                    # Теперь пробуем ещё один файл, и только два подряд
                    # egress-подобных отказа считаем блокировкой egress.
                    if any(
                        m in (error2 or "").lower()
                        for m in ("пустой ответ", "connection reset", "обрыв")
                    ):
                        egress_fail += 1
                        self._speed_failed[url] = self._speed_failed.get(url, 0) + 1
                        self._speed_error_reasons.setdefault(url, error2)
                        add_log(
                            "DEBUG",
                            f"Speed: узел закрывает соединение после CONNECT "
                            f"({egress_fail}/2) — пробую следующий файл",
                        )
                        if egress_fail >= 2:
                            add_log(
                                "DEBUG",
                                "Speed: два файла подряд не отдали данные после "
                                "CONNECT — похоже, egress заблокирован",
                            )
                            break
                        continue
            self._speed_failed[url] = self._speed_failed.get(url, 0) + 1
            if url not in self._speed_error_reasons:
                reason = error or "0 байт за окно"
                self._speed_error_reasons[url] = reason
                add_log(
                    "WARN",
                    f"Speed URL недоступен: {url.split('/')[2] if '://' in url else url} — "
                    f"{reason[:200]}",
                )
        return 0, 0

    def _measure_direct_and_save(self, url: str, window_sec: int) -> dict:
        """Прямой замер панели + сохранение baseline в настройках."""
        res = netcheck.measure_speed_direct(
            url or Settings.speed_test_url(), window_sec
        )
        payload = dict(res)
        payload["ts"] = time.time()
        payload["window_sec"] = window_sec
        Settings.set("speed_direct_last", json.dumps(payload, ensure_ascii=False))
        if res.get("ok"):
            add_log(
                "INFO",
                f"Direct speed: avg {res['avg_kbps']}kbps, max {res['max_kbps']}kbps, "
                f"{res['bytes']} байт за {res['elapsed']}с ({res['url']})",
            )
        else:
            add_log(
                "WARN",
                f"Direct speed failed: {res.get('error') or '0 байт'} ({res['url']})",
            )
        return res

    def speedtest_direct(self, url: str = "", window_sec: int | None = None) -> dict:
        """Ручной прямой замер (кнопка в настройках), без изменения профилей."""
        if not self._run_lock.acquire(blocking=False):
            return {"busy": True, "error": "Идёт проверка или замер — попробуйте позже"}
        try:
            window = int(window_sec or Settings.speed_test_duration_sec())
            return self._measure_direct_and_save(url.strip(), max(1, min(300, window)))
        finally:
            try:
                self._run_lock.release()
            except RuntimeError:
                pass

    def _stage_speed_direct(self, speed_rows):
        """Диагностический режим: один прямой замер вместо профилей."""
        with self._progress_lock:
            p = self.progress
            p["total"] = 1
            p["done"] = 0
            p["ok"] = 0
            p["current"] = "прямой замер панели"
            for st in p["stages"]:
                if st["status"] == "active":
                    st["total"] = 1
                    st["done"] = 0
                    st["ok"] = 0
        add_log(
            "WARN",
            "Speed: включён режим «прямой замер» — профили не обновляются, "
            "это диагностический baseline",
        )
        res = self._measure_direct_and_save(
            Settings.speed_test_url(), Settings.speed_test_duration_sec()
        )
        self._stage_advance(
            bool(res.get("ok")),
            current_text=(
                f"прямой: avg {res.get('avg_kbps', 0)} / max {res.get('max_kbps', 0)} kbps"
                if res.get("ok") else f"прямой: {res.get('error') or 'нет данных'}"
            ),
        )
        if speed_rows:
            add_log(
                "INFO",
                f"Speed: прямой режим пропустил {len(speed_rows)} профилей; "
                "верните «Через профили», чтобы обновить их скорость",
            )

    def _stage_speed(self, speed_rows, apply_incremental=False):
        """Стадия «Замер скорости» — СТРОГО по одному профилю за раз.

        Параллельные замеры скорости дают недостоверные данные (делят канал).
        Если включён `apply_incremental`, между замерами (то есть без нагрузки
        на измеряемый канал) конфиг и подписка обновляются: пользователь видит
        первые рабочие узлы через десятки секунд, а не после всей стадии.

        Если в настройках выключен режим «через профили», стадия не трогает
        профили и делает только один прямой baseline с панели. Это диагностика:
        сравнение с профильным замером показывает, где теряется скорость.
        """
        if not Settings.speed_use_profiles():
            self._stage_speed_direct(speed_rows)
            return
        window_sec = Settings.speed_test_duration_sec()
        budget = Settings.speed_stage_budget_sec()
        deadline = time.monotonic() + budget if budget else 0.0
        measured = 0
        self._speed_error_reasons = {}
        self._last_speed_xray_tail = ""
        last_apply = time.monotonic()
        changed_since_apply = False
        zero_streak = 0
        zero_warned = False

        def maybe_apply():
            nonlocal last_apply, changed_since_apply
            if not (apply_incremental and changed_since_apply):
                return
            if time.monotonic() - last_apply < INCREMENTAL_APPLY_SEC:
                return
            if self._apply_incremental(f"замерено {measured} профилей"):
                last_apply = time.monotonic()
                changed_since_apply = False

        for index, r in enumerate(speed_rows, start=1):
            if self._cancel.is_set():
                add_log("INFO", "Cancel requested, stopping speed stage")
                break
            if deadline and time.monotonic() > deadline:
                add_log(
                    "WARN",
                    f"Speed stage: бюджет {budget}с исчерпан — {measured} замеров, "
                    f"остальные профили пропущены. Увеличьте «Бюджет стадии» "
                    "или уменьшите «Топ-N».",
                )
                break
            # Применяем накопленные результаты перед стартом следующего замера:
            # так обновление конфига не влияет на сам замер скорости.
            maybe_apply()
            parsed = parse_vless(r["link"])
            host = r.get("host") or (parsed.get("server") if parsed else f"#{r['id']}")
            if not parsed:
                self._stage_advance(False, current_text=f"#{r['id']} {host}: invalid link")
                continue
            # Начало замера видно в логах: если профиль «завис», по логу понятно,
            # на каком именно это произошло (DEBUG, не ошибка).
            add_log(
                "DEBUG",
                f"Speed {index}/{len(speed_rows)}: #{r['id']} {host} — старт замера",
            )
            proc, tmp_path, http_port, _err = self._start_xray(parsed)
            if not proc:
                self._stage_advance(False, current_text=f"#{r['id']} {host}: xray start failed")
                changed_since_apply = True
                continue
            try:
                # Диагностика на первом профиле: проходит ли туннель URL проверки.
                # Если нет — проблема в самом туннеле, а не в файле замера; если
                # да, но файлы замера дают 503 — exit-нода не открывает цель.
                if index == 1:
                    try:
                        from .checker import probe_once

                        ok_probe, _lat, perr, _el = probe_once(
                            http_port,
                            min(6.0, float(Settings.probe_timeout())),
                            Settings.probe_url(),
                        )
                        add_log(
                            "DEBUG" if ok_probe else "WARN",
                            "Speed: туннель первого профиля "
                            + ("проходит URL проверки" if ok_probe else f"НЕ проходит URL проверки: {perr}"),
                        )
                    except Exception as e:  # noqa: BLE001 — диагностика не критична
                        add_log("DEBUG", f"Speed: диагностика туннеля не удалась: {e}")
                self._set_current(f"#{r['id']} {host} — замер {window_sec}с…")
                kbps, peak = self._measure_kbps(http_port, window_sec)
                if kbps:
                    measured += 1
                    zero_streak = 0
                    db_q(
                        "UPDATE proxies SET speed_kbps=?, speed_max_kbps=?, "
                        "speed_tested_at=?, speed_fail_count=0 WHERE id=?",
                        (kbps, peak, now_utc(), r["id"]),
                    )
                    add_log(
                        "INFO",
                        f"Speed #{r['id']} ({host}): avg {kbps}kbps, max {peak}kbps / "
                        f"{window_sec}s window",
                    )
                else:
                    zero_streak += 1
                    # Неудачная попытка тоже фиксируется: в следующем прогоне
                    # этот профиль уйдёт в конец очереди, а не будет снова
                    # первым съедать бюджет стадии.
                    db_q(
                        "UPDATE proxies SET speed_kbps=0, speed_max_kbps=0, "
                        "speed_tested_at=?, speed_fail_count=COALESCE(speed_fail_count, 0) + 1 "
                        "WHERE id=?",
                        (now_utc(), r["id"]),
                    )
                    add_log(
                        "WARN",
                        f"Speed #{r['id']} ({host}): no data in {window_sec}s window; "
                        "старая скорость сброшена",
                    )
                    xray_tail = self._speed_log_tail()
                    if xray_tail:
                        self._last_speed_xray_tail = xray_tail
                        add_log("DEBUG", f"Speed #{r['id']}: Xray: {xray_tail}")
                    if zero_streak >= 5 and not zero_warned:
                        zero_warned = True
                        add_log(
                            "WARN",
                            "Speed stage: 5 профилей подряд без данных — файл замера "
                            "недоступен с части exit-нод. Продолжаю по списку: "
                            "незамеренные профили получат попытку в следующих прогонах",
                        )
                changed_since_apply = True
                self._stage_advance(
                    kbps > 0,
                    current_text=(
                        f"#{r['id']} {host}: {kbps}kbps (макс {peak})"
                        if kbps else f"#{r['id']} {host}: 0 kbps"
                    ),
                )
            finally:
                self._stop_xray(proc, tmp_path)
        if speed_rows and measured == 0:
            reasons = "; ".join(
                f"{u.split('/')[2] if '://' in u else u}: {r[:120]}"
                for u, r in list(self._speed_error_reasons.items())[:5]
            )
            hint = (
                " Похоже, exit-ноды не пропускают файл замера (TLS/CONNECT/блокировка "
                "хостинга). Возьмите HTTP-файл, доступный из стран ваших exit-нод: "
                "из РФ — http://mirror.yandex.ru/debian/ls-lR.gz или "
                "http://speedtest.selectel.ru/10MB; из ЕС — "
                "http://ftp.bit.nl/speedtest/10mb.bin, и укажите его в «URL замера»."
            )
            add_log(
                "WARN",
                f"Speed stage: 0/{len(speed_rows)} measurements succeeded — "
                f"проверьте speed_test_url ({Settings.get('speed_test_url')}) "
                f"и доступность CDN с exit-нод."
                + (f" Причины: {reasons}." if reasons else "")
                + hint,
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
        # Пульс прогона: раз в 2 минуты пишем стадию/прогресс. Если прогон
        # «завис», в логах видно, на каком месте и в какой стадии это случилось.
        heartbeat_stop = threading.Event()
        threading.Thread(
            target=self._pipeline_heartbeat,
            args=(label, heartbeat_stop),
            daemon=True,
            name="pipeline-heartbeat",
        ).start()
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

            # Быстрый результат для пользователя: если политика допуска не
            # требует замера, применяем конфиг сразу после проверки — рабочие
            # узлы уже в конфиге и подписке, а скорость дозамерится на ходу.
            if (
                apply_config
                and not self._cancel.is_set()
                and working
                and not Settings.require_speed()
            ):
                self._apply_incremental("после проверки, до замеров скорости")

            if self._speed_enabled_for(working):
                speed_rows = self._speed_rows(row_ids)
                if speed_rows:
                    self._begin_stage("speed", "Замер скорости", len(speed_rows))
                    add_log("INFO", f"Speed stage ({label}): {len(speed_rows)} proxies, ONE AT A TIME, "
                                    f"{Settings.speed_test_duration_sec()}s each")
                    self._stage_speed(speed_rows, apply_incremental=apply_config)
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
            # Остановка панели во время прогона — не ошибка конвейера: пул
            # потоков уже не принимает задачи. Не пугаем пользователя ERROR'ом.
            if "interpreter shutdown" in str(e).lower() or sys.is_finalizing():
                add_log("INFO", f"Pipeline {label} остановлен: завершение процесса")
            else:
                add_log("ERROR", f"Pipeline {label} crashed: {e}")
            self._finish_run(label)
            return self._check_stats
        finally:
            heartbeat_stop.set()

    def _pipeline_heartbeat(self, label: str, stop: threading.Event) -> None:
        """Пишет в лог, что прогон жив и где он находится (раз в 2 минуты)."""
        while not stop.wait(120):
            try:
                p = self.progress_snapshot()
                if not p.get("running"):
                    continue
                elapsed_min = int((time.time() - (p.get("started_at") or 0)) / 60)
                add_log(
                    "INFO",
                    f"Прогон «{label}» идёт: стадия {p.get('phase') or '—'}, "
                    f"{p.get('done', 0)}/{p.get('total', 0)}, "
                    f"текущий: {p.get('current') or '—'}, прошло ~{elapsed_min} мин",
                )
            except Exception:  # noqa: BLE001 — пульс не должен ломать прогон
                pass

    def _apply_incremental(self, reason: str) -> bool:
        """Промежуточное применение конфига и подписки во время прогона.

        Не блокирует прогон: если пересборка уже идёт, просто пропускаем —
        следующая попытка будет между следующими замерами.
        """
        from .xray_configurator import xray_configurator

        if xray_configurator.apply_all(blocking=False):
            add_log("INFO", f"Конфиг и подписка обновлены на ходу ({reason})")
            return True
        return False

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
        """Топ-N рабочих профилей прогона по пингу для замера скорости.

        Очерёдность: сначала **никогда не замерявшиеся**, потом уже пытавшиеся
        (старые попытки — первыми), затем замеренные (для освежения значений).
        Раньше первые места по пингу стабильно занимали одни и те же узлы: если
        файл замера у них недоступен, они оставались «незамеренными» и каждый
        прогон снова съедали бюджет стадии. Теперь неудачная попытка сдвигает
        профиль назад — за прогоны очередь реально двигается.
        """
        speed_max = int(Settings.get("speed_test_max", "8"))
        if speed_max <= 0:
            return []
        placeholders = ",".join("?" * len(row_ids))
        return [
            dict(r)
            for r in db_q(
                f"SELECT id, link, host FROM proxies WHERE id IN ({placeholders}) "
                f"AND status='working' AND latency_vless > 0 "
                f"ORDER BY CASE "
                f"  WHEN COALESCE(speed_kbps, 0) > 0 THEN 2 "
                f"  WHEN COALESCE(speed_fail_count, 0) > 0 THEN 1 "
                f"  ELSE 0 END ASC, "
                # Среди ни разу не замерявшихся — случайная выборка, а не
                # строго самый низкий пинг: иначе каждый прогон упирается в
                # одни и те же узлы (часто одного «фильтрующего» оператора),
                # и до узлов с нормальным egress очередь не доходит.
                f"CASE WHEN COALESCE(speed_kbps, 0) = 0 "
                f"     AND COALESCE(speed_fail_count, 0) = 0 THEN RANDOM() ELSE 0 END, "
                f"COALESCE(speed_tested_at, '') ASC, "
                f"latency_vless ASC, id ASC LIMIT ?",
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

    def start_refresh_stale(self) -> dict:
        """Актуализация: прогон по профилям с протухшим доказательством.

        Берутся только рабочие профили, которые политика допуска уже не пускает
        в конфиг: устаревшие (проверка давно не проходила) и незамеренные.
        «Тест всех» для этого не нужен: он гоняет и мёртвые профили.
        """
        from .selection import retest_targets

        targets = retest_targets()
        if not targets:
            add_log("INFO", "Refresh stale: нет профилей с устаревшим доказательством")
            return {"started": False, "queued": 0, "reason": "нет устаревших профилей"}
        ids = [t["id"] for t in targets]
        rows = db_q(
            f"SELECT id, link, host FROM proxies WHERE id IN ({','.join('?' * len(ids))})",
            ids,
        )
        if not rows:
            return {"started": False, "queued": 0, "reason": "профили не найдены"}
        started = self._start_background(
            [dict(r) for r in rows],
            "refresh-stale",
            apply_config=True,
            apply_blocking=True,
        )
        if not started:
            return {"started": False, "busy": True, "queued": 0}
        # Сколько из них реально успеет замериться за бюджет стадии скорости:
        # замер идёт по одному профилю фиксированное окно, и при маленьком
        # бюджете часть прогона — честная проверка без замера.
        speed_max = int(Settings.get("speed_test_max", "8") or 0)
        window = Settings.speed_test_duration_sec()
        budget = Settings.speed_stage_budget_sec()
        planned = min(len(rows), speed_max) if speed_max > 0 else 0
        estimated = planned * window
        add_log(
            "INFO",
            f"Refresh stale queued: {len(rows)} proxies (устаревших/без замера); "
            f"замеров в прогоне: {planned}, ~{estimated}с при бюджете {budget or '∞'}с",
        )
        return {
            "started": True,
            "queued": len(rows),
            "speed_measurements": planned,
            "speed_estimate_sec": estimated,
            "speed_budget_sec": budget,
            "speed_will_truncate": bool(budget and estimated > budget),
        }

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

    def measure_single(self, pid: int, speed_url: str = "") -> dict:
        """Полный конвейер для ОДНОГО прокси (синхронно, эксклюзивно).

        speed_url — проверить именно этот URL замера (для диагностики:
        «скачивается ли файл через этот конкретный профиль»).
        Возвращает {busy:True} если идёт другой замер, иначе результат.
        """
        rows = db_q("SELECT id, link, host FROM proxies WHERE id=?", (pid,))
        if not rows:
            return {"busy": False, "error": "not found"}
        row = rows[0]
        if not self._run_lock.acquire(blocking=False):
            snap = self.progress_snapshot()
            add_log("WARN", f"Another test is running — single test #{pid} skipped")
            return {
                "busy": True,
                "running_label": snap.get("label") or snap.get("last_label") or "",
                "phase": snap.get("phase") or "",
                "done": snap.get("done", 0),
                "total": snap.get("total", 0),
                "current": snap.get("current") or "",
            }
        self._speed_url_override = (speed_url or "").strip()
        self._last_speed_xray_tail = ""
        try:
            self._execute_pipeline(
                [row], "single", apply_config=False,
                timeout=float(Settings.vless_per_proxy_timeout()),
            )
            after = db_q(
                "SELECT status, latency, latency_vless, speed_kbps, speed_max_kbps, "
                "last_error FROM proxies WHERE id=?",
                (pid,),
            )
            if not after:
                return {"busy": False, "error": "deleted during test"}
            r = after[0]
            speed = r["speed_kbps"] or 0
            if r["status"] == "working":
                # Страну определяем только для рабочих профилей. Одиночный
                # тест мог только что сделать профиль рабочим — запускаем
                # фоновое обогащение, не дожидаясь следующего прогона.
                schedule_country_enrichment()
            direct = Settings.speed_direct_last()
            # Для диагностики: если скорость 0 — отдаём причину по URL (важнее),
            # а лог Xray — отдельным полем.
            speed_error = ""
            if not speed:
                if self._speed_error_reasons:
                    speed_error = next(iter(self._speed_error_reasons.values()))
                elif self._last_speed_xray_tail:
                    speed_error = self._last_speed_xray_tail
            return {
                "busy": False,
                "status": r["status"],
                "latency": r["latency_vless"] or 0,
                "speed": speed,
                "speed_max": r["speed_max_kbps"] or 0,
                "direct_avg_kbps": int(direct.get("avg_kbps") or 0),
                "direct_max_kbps": int(direct.get("max_kbps") or 0),
                "speed_url": self._speed_url_override or Settings.speed_test_url(),
                "speed_error": speed_error,
                "speed_errors": dict(self._speed_error_reasons),
                "xray_log": self._last_speed_xray_tail,
                "error": r["last_error"] or (None if r["status"] == "working" else "test failed"),
            }
        finally:
            self._speed_url_override = ""
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
        """Лёгкий фоновый поток: проверяет каждые 30 сек, совпадает ли набор
        node-outbound в работающем Xray с тем, что отбирает политика допуска.

        Сравниваются именно теги, а не количество: раньше позиционные теги
        (node0, node1, ...) после пересортировки означали другие профили, и
        «то же количество» скрывало полностью другой набор узлов. Плюс память
        применённого набора (applied_node_tags) ловит случай, когда hot-reload
        не удался и конфиг на диске новее работающего Xray.
        """
        add_log("INFO", "Failover checker started (interval: 30s)")
        while not self._shutdown.is_set():
            if self._shutdown.wait(timeout=30):
                break
            try:
                from .selection import config_rows, node_tag
                from .xray_configurator import xray_configurator

                if not xray_configurator.api_ok():
                    continue

                # Пока идёт тест, статусы в БД ещё меняются: если пересобирать
                # конфиг в этот момент, получим ложный рассинхрон и лишние
                # пересборки каждые 30 сек.
                if self._vless_busy:
                    continue

                max_active = Settings.max_active_proxies()
                expected_tags = {
                    node_tag(r["id"])
                    for r in config_rows(max_active).rows
                }
                live = xray_configurator.live_node_tags()
                known = set(Settings.applied_node_tags())
                now = time.time()

                if live and live != expected_tags:
                    if now - self._last_failover_apply > 120:
                        self._last_failover_apply = now
                        add_log(
                            "WARN",
                            f"Failover: в Xray {len(live)} node-outbound, ожидается "
                            f"{len(expected_tags)} — пересборка конфига",
                        )
                        xray_configurator.apply_all(blocking=False)
                elif not live and known != expected_tags:
                    # statsquery молчит (счётчиков ещё нет) — сверяемся с памятью
                    # применённого набора. Не чаще раза в 5 минут, чтобы не
                    # дёргать API на каждом цикле.
                    if now - self._last_failover_apply > 300:
                        self._last_failover_apply = now
                        add_log(
                            "WARN",
                            f"Failover: применено {len(known)} outbound, ожидается "
                            f"{len(expected_tags)} — пересборка конфига",
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
