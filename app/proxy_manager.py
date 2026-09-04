"""Управление прокси: тестирование, обновление статуса, фоновые задачи."""

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


class ProxyManager:
    """Тестирование прокси, обновление статусов, фоновый циклический чекер."""

    def __init__(self):
        self._vless_busy = False
        self._last_run_db = 0.0
        self._last_run_import = 0.0
        self._shutdown = threading.Event()
        self._cancel = threading.Event()
        self._xray_children: dict[int, subprocess.Popen] = {}
        self._xray_children_lock = threading.Lock()
        signal.signal(signal.SIGTERM, self._signal_handler)
        self.progress = {
            "running": False,
            "total": 0,
            "done": 0,
            "ok": 0,
            "label": "",
            "last_completed": "",
            "last_label": "",
            "last_ok": 0,
            "last_total": 0,
            "started_at": 0.0,
        }
        self._progress_lock = threading.Lock()

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

    # ─── VLESS test (single proxy) ───

    def test_vless_real(self, link, timeout=None):
        """Тестирует один VLESS-прокси через временный Xray-процесс.
        timeout=None — берётся из настроек (vless_per_proxy_timeout),
        чтобы одиночный тест из UI совпадал по таймауту с пакетным.
        Возвращает (ok, latency_ms, error).
        """
        if timeout is None:
            timeout = Settings.vless_per_proxy_timeout()
        parsed = parse_vless(link)
        if not parsed:
            return False, 0, "invalid link"
        return self._test_vless(parsed, timeout)

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

    @staticmethod
    def _test_vless(parsed, timeout):
        """Запускает Xray с конфигом для одного прокси, тестирует, убивает.
        Возвращает (ok, latency_ms, error)."""
        proc, tmp_path, http_port, err = ProxyManager._start_xray(parsed)
        if not proc:
            return False, 0, err or "xray start failed"
        try:
            return ProxyManager._probe(http_port, timeout)
        except Exception as e:
            add_log("ERROR", f"VLESS test failed: {e}")
            return False, 0, "internal test error"
        finally:
            ProxyManager._stop_xray(proc, tmp_path)

    # ─── Speed test ───

    @staticmethod
    def _measure_kbps(http_port, timeout=15):
        """Скачивает speed-test файл через HTTP-прокси, возвращает kbps.
        Пробует несколько URL по порядку, пока один не сработает."""
        urls = [
            Settings.get("speed_test_url", ""),
            "https://www.google.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png",
            "https://httpbin.org/bytes/102400",
            "http://speedtest.selectel.ru/1MB",
        ]
        urls = [u for u in urls if u]
        for url in urls:
            kbps = ProxyManager._measure_url_kbps(http_port, url, timeout)
            if kbps:
                return kbps
        return 0

    @staticmethod
    def _measure_url_kbps(http_port, url, timeout=15):
        """Скачивает URL через HTTP-прокси, возвращает kbps.

        Окно замера длится минимум speed_test_min_sec (по умолчанию 10 с):
        если файл кончился раньше, повторно открываем его, пока не наберём
        минимальное время, либо не упрёмся в таймаут.
        Adaptive: ранний выход только после минимального окна, если скорость
        уже явно выше min_speed.
        """
        proxy_url = f"http://127.0.0.1:{http_port}"
        proxy_handler = urllib.request.ProxyHandler(
            {"http": proxy_url, "https": proxy_url}
        )
        opener = urllib.request.build_opener(proxy_handler)
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                },
            )
            req_start = time.time()
            resp = opener.open(req, timeout=timeout)
            total = 0
            min_kbps = Settings.min_speed_kbps()
            adaptive_sec = Settings.speed_test_adaptive_sec()
            min_sec = Settings.speed_test_min_sec()
            while True:
                buf = resp.read(131072)
                elapsed = time.time() - req_start
                if buf:
                    total += len(buf)
                if not buf:
                    # Файл исчерпан. Если окно замера ещё не набрано — качаем ещё раз.
                    if total > 0 and elapsed < min_sec and elapsed < timeout - 1:
                        try:
                            resp = opener.open(
                                req, timeout=max(3, int(timeout - elapsed) + 1)
                            )
                            continue
                        except Exception:
                            break
                    break
                if elapsed >= timeout:
                    break
                # Adaptive: ранний выход только после минимального окна замера
                if min_kbps > 0 and elapsed >= max(adaptive_sec, min_sec) and total > 0:
                    cur = int((total * 8) / (elapsed * 1000))
                    if cur >= min_kbps * 1.3:
                        return cur
            elapsed = time.time() - req_start
            if elapsed > 0 and total > 0:
                return int((total * 8) / (elapsed * 1000))
        except Exception as e:
            add_log("DEBUG", f"Speed measure {url}: {e}")
        return 0

    def _test_speed_single(self, link, timeout=15):
        parsed = parse_vless(link)
        if not parsed:
            return 0
        proc, tmp_path, http_port, _err = ProxyManager._start_xray(parsed)
        if not proc:
            return 0
        try:
            return ProxyManager._measure_kbps(http_port, timeout)
        except Exception as e:
            add_log("DEBUG", f"Speed test failed: {e}")
            return 0
        finally:
            ProxyManager._stop_xray(proc, tmp_path)

    # ─── Status update ───

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

    def _record_completion(self, label):
        with self._progress_lock:
            self.progress.update(
                last_completed=moscow_str(),
                last_label=label,
                last_ok=self.progress["ok"],
                last_total=self.progress["total"],
                started_at=0.0,
            )
            self.progress["running"] = False

    # ─── Single test entry point (from API) ───

    def test_and_update_vless(self, link):
        ok, lat, err = self.test_vless_real(link)
        row = db_q("SELECT id FROM proxies WHERE link=?", (link,))
        if row:
            pid = row[0]["id"]
            self._update_vless_status(pid, ok, lat if ok else 0, err if not ok else "")
            detail = f" ({lat}ms)" if ok else f" — {err}"
            add_log("INFO", f"VLESS test #{pid} -> {'working' if ok else 'failed'}{detail}")

    # ─── Parallel batch testing (spawn/kill + inline speed) ───

    def _test_one_spawn(self, r, timeout):
        """VLESS-тест одного прокси (без speed test — вынесен в отдельный проход)."""
        if self._cancel.is_set():
            # Отмена: не трогаем статус в БД, но прогресс держим консистентным
            with self._progress_lock:
                self.progress["done"] += 1
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
        with self._progress_lock:
            self.progress["done"] += 1
            if ok:
                self.progress["ok"] += 1
                self._run_ok += 1
            else:
                key = ProxyManager._reason_bucket(err)
                self._run_reasons[key] = self._run_reasons.get(key, 0) + 1
        add_log(
            "DEBUG",
            f"Test proxy #{r['id']} -> {'working (' + str(lat) + 'ms)' if ok else 'failed (' + err + ')'}",
        )
        return r["id"], ok

    def _run_speed_test_pass(self, rows, label):
        """Отдельный проход speed test для top-N рабочих прокси.
        Запускается после VLESS-теста, чтобы не замедлять основной цикл."""
        speed_enabled = Settings.get("speed_test_enabled", "true") == "true"
        if not speed_enabled:
            return
        speed_max = int(Settings.get("speed_test_max", "30"))
        if speed_max <= 0:
            return

        # Берём top-N рабочих прокси из ТЕКУЩЕГО прогона (проверенных только что),
        # отсортированных по latency — не тратим время на прокси из прошлых циклов.
        row_ids = [r["id"] for r in rows if r.get("id")]
        if not row_ids:
            return
        placeholders = ",".join("?" * len(row_ids))
        working = db_q(
            f"SELECT id, link FROM proxies WHERE id IN ({placeholders}) AND status='working' ORDER BY latency_vless ASC LIMIT ?",
            row_ids + [speed_max],
        )
        if not working:
            return

        add_log("INFO", f"Speed test pass: {len(working)} proxies ({label})")
        tested = 0
        for r in working:
            if self._cancel.is_set():
                break
            parsed = parse_vless(r["link"])
            if not parsed:
                continue
            proc, tmp_path, http_port, _err = ProxyManager._start_xray(parsed)
            if not proc:
                continue
            try:
                speed_timeout = int(Settings.get("vless_per_proxy_timeout", "5")) * 3
                kbps = ProxyManager._measure_kbps(http_port, speed_timeout)
                if kbps:
                    db_q("UPDATE proxies SET speed_kbps=? WHERE id=?", (kbps, r["id"]))
                    tested += 1
                    add_log("INFO", f"Speed test #{r['id']}: {kbps}kbps")
            finally:
                ProxyManager._stop_xray(proc, tmp_path)
        add_log("INFO", f"Speed test pass done: {tested}/{len(working)} measured ({label})")

    @staticmethod
    def _reason_bucket(err) -> str:
        """Нормализует причину отказа для сводной статистики прогона."""
        err = (err or "").strip()
        if not err:
            return "unknown"
        if err.startswith("xray binary not found"):
            return "xray binary not found"
        return err[:60]

    def _run_batch(self, rows, label, timeout):
        if not rows:
            return
        cid = uuid.uuid4().hex[:12]
        set_correlation_id(cid)
        with self._progress_lock:
            self.progress.update(running=True, total=len(rows), done=0, ok=0, label=label, started_at=time.time())
            self._run_reasons = {}
            self._run_ok = 0
        self._cancel.clear()
        try:
            add_log("INFO", f"Testing {label}: {len(rows)} proxies")
            max_workers = Settings.max_workers()
            with ThreadPoolExecutor(max_workers=max_workers) as tpool:
                futures = {tpool.submit(self._test_one_spawn, r, timeout): r for r in rows}
                for f in as_completed(futures):
                    if self._cancel.is_set():
                        add_log("INFO", f"Cancel requested, stopping {label}")
                        for ff in futures:
                            ff.cancel()
                        break
            from .utils import enrich_all_unknown_countries

            enrich_all_unknown_countries()

            # Speed test отдельным проходом (не блокирует VLESS-тест)
            self._run_speed_test_pass(rows, label)

            with self._progress_lock:
                ok_cnt = self.progress["ok"]
                done_cnt = self.progress["done"]
                reasons = sorted(self._run_reasons.items(), key=lambda kv: (-kv[1], kv[0]))
            parts = [f"{k}: {v}" for k, v in reasons[:6]]
            if len(reasons) > 6:
                parts.append(f"прочие: {sum(v for _, v in reasons[6:])}")
            summary = f"{label}: ok {ok_cnt}/{done_cnt}"
            if parts:
                summary += " · не работают: " + ", ".join(parts)
            add_log("INFO", f"{summary} · {moscow_str()}")
        finally:
            self._record_completion(label)

    def test_all_vless(self):
        """Тест всех прокси из БД (без импорта).
        Возвращает True если тест запущен, False если пропущен."""
        if self._vless_busy:
            add_log("WARN", "Test already in progress, ignoring test_all_vless")
            return False
        rows = db_q("SELECT id, link FROM proxies")
        if not rows:
            add_log("WARN", "Test all VLESS: no proxies to test")
            return False
        self._bg_vless_batch(rows, "all")
        from .xray_configurator import xray_configurator

        xray_configurator.apply_all(blocking=True)
        return True

    def batch_test_vless(self, rows, label="batch-test"):
        """Возвращает True если тест запущен, False если пропущен."""
        if self._vless_busy:
            add_log("WARN", "Test already in progress, ignoring batch_test_vless")
            return False
        self._bg_vless_batch(rows, label)
        from .xray_configurator import xray_configurator

        xray_configurator.apply_all(blocking=True)
        return True

    # ─── Background tasks ───

    def _bg_vless_batch(self, rows, label):
        self._vless_busy = True
        try:
            self._run_batch(
                rows,
                label,
                Settings.vless_per_proxy_timeout(),
            )
        finally:
            self._vless_busy = False

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
                due_import = (
                    now - self._last_run_import >= Settings.check_interval_import()
                )
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
        """Импорт из источников → проверка прокси → сборка конфига."""
        self._vless_busy = True
        try:
            src_list = db_q("SELECT id, url, type FROM sources")
            for src in src_list:
                if src["type"] == "txt":
                    import_from_txt(src["id"])
                else:
                    import_from_url(src["url"], source_id=src["id"])
            from .utils import enrich_all_unknown_countries

            enrich_all_unknown_countries()

            rows = db_q("SELECT id, link FROM proxies")
            if rows:
                add_log("INFO", f"Import+check: {len(rows)} proxies")
                self._bg_vless_batch(rows, "import+check")
            # import+check протестировал все прокси — db-check не нужен
            self._last_run_db = time.time()

            if Settings.get("apply_after_test", "true") == "true":
                from .xray_configurator import xray_configurator

                xray_configurator.apply_all()
                add_log("INFO", "Import+check cycle completed")
        except Exception as e:
            add_log("ERROR", f"Import+check cycle crashed: {e}")
        finally:
            self._vless_busy = False

    def _run_db_chain(self):
        """Проверка прокси из БД (без импорта) → сборка конфига."""
        self._vless_busy = True
        try:
            rows = db_q("SELECT id, link FROM proxies")

            if rows:
                add_log("INFO", f"DB check: {len(rows)} proxies")
                self._bg_vless_batch(rows, "db-check")

            if Settings.get("db_check_auto_cleanup", "false") == "true":
                deleted = db_q("SELECT COUNT(*) c FROM proxies WHERE status='failed'")[0]["c"]
                if deleted:
                    db_q("DELETE FROM proxies WHERE status='failed'")
                    add_log("INFO", f"DB check auto-cleanup: deleted {deleted} failed proxies")

            if Settings.get("apply_after_test", "true") == "true":
                from .xray_configurator import xray_configurator

                xray_configurator.apply_all()
                add_log("INFO", "DB check cycle completed")
        except Exception as e:
            add_log("ERROR", f"DB check cycle crashed: {e}")
        finally:
            self._vless_busy = False


proxy_manager = ProxyManager()
