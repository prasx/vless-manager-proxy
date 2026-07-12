"""Управление прокси: тестирование, обновление статуса, фоновые задачи."""

import json
import os
import re
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

from config import SOCKS_PORT, HTTP_PORT
from .db import db_q, Settings
from .utils import add_log, now_utc, moscow_str, set_correlation_id, count_active_connections
from .importer import import_from_url
from .vless import parse_vless, stream_settings


class ProxyManager:
    """Тестирование прокси, обновление статусов, фоновый циклический чекер."""

    def __init__(self):
        self._vless_busy = False
        self._last_run_db = 0.0
        self._last_run_import = 0.0
        self._speed_test_done = 0
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

    def test_vless_real(self, link, timeout=3):
        """Тестирует один VLESS-прокси через временный Xray-процесс.
        Возвращает (ok, latency_ms).
        """
        xbin = Settings.xray_bin()
        if not Path(xbin).is_file():
            add_log("ERROR", f"VLESS test: xray binary not found at {xbin}")
            return False, 0

        parsed = parse_vless(link)
        if not parsed:
            return False, 0

        return self._test_vless(parsed, timeout)

    @staticmethod
    def _probe(http_port, timeout):
        probe_url = Settings.probe_url()
        proxy_url = f"http://127.0.0.1:{http_port}"
        proxy_handler = urllib.request.ProxyHandler(
            {"http": proxy_url, "https": proxy_url}
        )
        opener = urllib.request.build_opener(proxy_handler)
        req_start = time.time()
        try:
            resp = opener.open(probe_url, timeout=max(2, timeout - 1))
            ok = resp.status < 400
            lat = int((time.time() - req_start) * 1000)
            return ok, lat
        except Exception as e:
            add_log("DEBUG", f"Probe failed: {e}")
            return False, 0

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
        """Запускает Xray для одного прокси. Возвращает (proc, tmp_path, http_port) или (None, None, None)."""
        xbin = Settings.xray_bin()
        if not Path(xbin).is_file():
            return None, None, None
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
                    return proc, tmp_path, http_port
                except (OSError, ConnectionRefusedError):
                    time.sleep(0.05)
        except Exception:
            pass
        ProxyManager._stop_xray(proc, tmp_path)
        return None, None, None

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
        """Запускает Xray с конфигом для одного прокси, тестирует, убивает."""
        proc, tmp_path, http_port = ProxyManager._start_xray(parsed)
        if not proc:
            return False, 0
        try:
            return ProxyManager._probe(http_port, timeout)
        except Exception as e:
            add_log("ERROR", f"VLESS test failed: {e}")
            return False, 0
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
        Adaptive: ранний выход если скорость явно выше min_speed."""
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
            while True:
                buf = resp.read(131072)
                if not buf:
                    break
                total += len(buf)
                elapsed = time.time() - req_start
                if elapsed >= timeout:
                    break
                # Adaptive: если скорость уже явно выше порога — хватит
                if min_kbps > 0 and elapsed >= adaptive_sec and total > 0:
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
        proc, tmp_path, http_port = ProxyManager._start_xray(parsed)
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
    def _update_vless_status(pid, ok, lat_vless):
        now = now_utc()
        if ok:
            db_q(
                "UPDATE proxies SET status='working', latency=?, latency_vless=?, failed_since=NULL WHERE id=?",
                (lat_vless, lat_vless, pid),
            )
        else:
            db_q(
                "UPDATE proxies SET status='failed', latency=0, latency_vless=0, speed_kbps=0, failed_since=COALESCE(failed_since, ?) WHERE id=?",
                (now, pid),
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
        ok, lat = self.test_vless_real(link)
        row = db_q("SELECT id FROM proxies WHERE link=?", (link,))
        if row:
            self._update_vless_status(row[0]["id"], ok, lat if ok else 0)
            add_log(
                "INFO",
                f"VLESS test {link[:50]} -> {'working' if ok else 'failed'} ({lat}ms)",
            )

    # ─── Parallel batch testing (spawn/kill + inline speed) ───

    def _test_one_spawn(self, r, timeout):
        """Fallback: spawn/kill Xray на каждый прокси + inline speed."""
        parsed = parse_vless(r["link"])
        ok = False
        lat = 0
        speed_kbps = 0
        proc, tmp_path, http_port = ProxyManager._start_xray(parsed) if parsed else (None, None, None)
        if proc:
            ok, lat = ProxyManager._probe(http_port, timeout)
            if ok:
                speed_enabled = Settings.get("speed_test_enabled", "true") == "true"
                speed_max = int(Settings.get("speed_test_max", "30"))
                if speed_enabled and self._speed_test_done < speed_max:
                    speed_timeout = timeout * 3
                    speed_kbps = ProxyManager._measure_kbps(http_port, speed_timeout)
                    if speed_kbps:
                        self._speed_test_done += 1
            ProxyManager._stop_xray(proc, tmp_path)
        self._update_vless_status(r["id"], ok, lat if ok else 0)
        if speed_kbps:
            db_q("UPDATE proxies SET speed_kbps=? WHERE id=?", (speed_kbps, r["id"]))
        with self._progress_lock:
            self.progress["done"] += 1
            if ok:
                self.progress["ok"] += 1
        add_log(
            "INFO",
            f"Test proxy #{r['id']} -> {'working' if ok else 'failed'} ({lat}ms)" +
            (f" speed={speed_kbps}kbps" if speed_kbps else ""),
        )
        return r["id"], ok

    def _run_batch(self, rows, label, timeout):
        if not rows:
            return
        cid = uuid.uuid4().hex[:12]
        set_correlation_id(cid)
        with self._progress_lock:
            self.progress.update(running=True, total=len(rows), done=0, ok=0, label=label, started_at=time.time())
        self._speed_test_done = 0
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
            vless_ok = self.progress["ok"]
            vless_total = self.progress["total"]
            from .utils import enrich_all_unknown_countries

            enrich_all_unknown_countries()

            add_log(
                "INFO",
                f"{label}: {vless_ok}/{vless_total} ok, {self._speed_test_done} speed — {moscow_str()}",
            )
        finally:
            self._record_completion(label)

    def test_all_vless(self):
        """Тест всех прокси из БД (без импорта)."""
        if self._vless_busy:
            add_log("WARN", "Test already in progress, ignoring test_all_vless")
            return
        rows = db_q("SELECT id, link FROM proxies")
        if not rows:
            add_log("WARN", "Test all VLESS: no proxies to test")
            return
        self._bg_vless_batch(rows, "all")
        from .xray_configurator import xray_configurator

        xray_configurator.apply_all(blocking=True)

    def batch_test_vless(self, rows):
        if self._vless_busy:
            add_log("WARN", "Test already in progress, ignoring batch_test_vless")
            return
        self._bg_vless_batch(rows, "batch-test")
        from .xray_configurator import xray_configurator

        xray_configurator.apply_all(blocking=True)

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

    def _run_import_chain(self):
        """Импорт из источников → проверка прокси → сборка конфига."""
        self._vless_busy = True
        try:
            src_list = db_q("SELECT id, url FROM sources")
            for src in src_list:
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

            if Settings.get("apply_after_test", "true") == "true":
                from .xray_configurator import xray_configurator

                xray_configurator.apply_all()
                add_log("INFO", "DB check cycle completed")
        except Exception as e:
            add_log("ERROR", f"DB check cycle crashed: {e}")
        finally:
            self._vless_busy = False


    _nft_inited = False

    def _nft_init(self):
        """Удаляет старые iptables-compat правила, добавляет nftables счётчики на прокси-порты."""
        if self._nft_inited:
            return True
        try:
            # 1. Создаём таблицу + базовые цепочки, если их нет (на чистой Ubuntu их нет)
            subprocess.run(["nft", "add", "table", "ip", "filter"],
                           capture_output=True, timeout=5)
            for name, hook in (
                ("INPUT",  "type filter hook input priority 0;"),
                ("OUTPUT", "type filter hook output priority 0;"),
            ):
                subprocess.run(
                    ["nft", "add", "chain", "ip", "filter", name, "{" + hook + "}"],
                    capture_output=True, timeout=5,
                )
            # 2. удаляем старые правила с jump VLESS_MGR (от iptables-compat) — у них handle в nft
            for chain in ("INPUT", "OUTPUT"):
                # получаем хендлы правил
                r = subprocess.run(
                    ["nft", "-a", "list", "chain", "ip", "filter", chain],
                    capture_output=True, text=True, timeout=5,
                )
                for line in r.stdout.splitlines():
                    if "jump VLESS_MGR" not in line:
                        continue
                    # match: ... # handle N
                    m = re.search(r'# handle (\d+)', line)
                    if m:
                        h = m.group(1)
                        subprocess.run(
                            ["nft", "delete", "rule", "ip", "filter", chain, f"handle {h}"],
                            capture_output=True, timeout=5,
                        )
            # удаляем старую цепочку VLESS_MGR (если осталась без правил)
            subprocess.run(
                ["nft", "delete", "chain", "ip", "filter", "VLESS_MGR"],
                capture_output=True, timeout=5,
            )
            # добавляем свои правила-счётчики (в начало цепочки: insert = position 0)
            for cmd in (
                ["nft", "insert", "rule", "ip", "filter", "INPUT", "tcp", "dport", str(SOCKS_PORT), "counter", "accept"],
                ["nft", "insert", "rule", "ip", "filter", "INPUT", "tcp", "dport", str(HTTP_PORT), "counter", "accept"],
                ["nft", "insert", "rule", "ip", "filter", "OUTPUT", "tcp", "sport", str(SOCKS_PORT), "counter", "accept"],
                ["nft", "insert", "rule", "ip", "filter", "OUTPUT", "tcp", "sport", str(HTTP_PORT), "counter", "accept"],
            ):
                subprocess.run(cmd, capture_output=True, timeout=5)
            self._nft_inited = True
            add_log("INFO", "nftables proxy counters added")
            return True
        except Exception as e:
            add_log("WARN", f"nft init failed: {e}")
            return False

    def _nft_read(self):
        """Читает кумулятивные байты из nftables (текстовый парсинг).
        Возвращает (downlink_bytes=OUTPUT, uplink_bytes=INPUT)."""
        down = 0; up = 0
        socks = str(SOCKS_PORT); http = str(HTTP_PORT)
        for chain, direction in (("OUTPUT", "down"), ("INPUT", "up")):
            try:
                r = subprocess.run(
                    ["nft", "list", "chain", "ip", "filter", chain],
                    capture_output=True, text=True, timeout=5,
                )
            except Exception as e:
                add_log("DEBUG", f"nft read {chain}: {e}")
                continue
            for line in r.stdout.splitlines():
                if socks not in line and http not in line:
                    continue
                m = re.search(r'bytes\s+(\d+)', line)
                if m:
                    val = int(m.group(1))
                    if direction == "down":
                        down += val
                    else:
                        up += val
        return down, up

    def _collect_traffic(self):
        """Один цикл сбора: соединения через ss, трафик через nftables."""
        try:
            if not self._nft_inited:
                self._nft_init()
            raw_down, raw_up = self._nft_read()

            conns = count_active_connections([SOCKS_PORT, HTTP_PORT])
            total_conn = conns.get(SOCKS_PORT, 0) + conns.get(HTTP_PORT, 0)

            db_q(
                "INSERT INTO traffic_history (collected_at, total_downlink, total_uplink, active_outbounds, active_connections) VALUES (?, ?, ?, ?, ?)",
                (now_utc(), raw_down, raw_up, 0, total_conn),
            )

            trim_hours = Settings.traffic_history_hours()
            db_q(
                f"DELETE FROM traffic_history WHERE collected_at < datetime('now', '-{trim_hours} hours')"
            )
        except Exception as e:
            add_log("DEBUG", f"Traffic collector: {e}")

    def traffic_collector_loop(self):
        """Фоновый сборщик статистики трафика и активных соединений."""
        add_log("INFO", "Traffic collector loop started")
        # Первый сбор сразу
        self._collect_traffic()
        while not self._shutdown.is_set():
            if self._shutdown.wait(timeout=Settings.traffic_collect_interval()):
                break
            self._collect_traffic()

    def get_live_traffic(self):
        """Возвращает (raw_down_bytes, raw_up_bytes) напрямую из nftables (real-time)."""
        try:
            if not self._nft_inited:
                self._nft_init()
            return self._nft_read()
        except Exception as e:
            add_log("DEBUG", f"get_live_traffic: {e}")
            return 0, 0

    def start_traffic_collector(self):
        """Запускает фоновый поток сбора статистики трафика."""
        t = threading.Thread(target=self.traffic_collector_loop, daemon=True)
        t.start()


proxy_manager = ProxyManager()
