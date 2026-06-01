"""Управление прокси: тестирование, обновление статуса, фоновые задачи."""

import json
import os
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .db import db_q, Settings
from .utils import add_log, now_utc, moscow_str
from .importer import import_from_url
from .vless import parse_vless, stream_settings, sanitize_flow


class ProxyManager:
    """Тестирование прокси, обновление статусов, фоновый циклический чекер."""

    def __init__(self):
        self._vless_busy = False
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
        }
        self._progress_lock = threading.Lock()
        self._apply_lock = threading.Lock()
        self._last_apply_time = 0.0

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
            resp = opener.open(probe_url, timeout=timeout)
            ok = resp.status == 204
            lat = int((time.time() - req_start) * 1000)
            return ok, lat
        except Exception as e:
            add_log("DEBUG", f"Probe failed: {e}")
            return False, 0

    @staticmethod
    def _test_vless(parsed, timeout):
        """Запускает Xray с конфигом для одного прокси, тестирует, убивает."""
        xbin = Settings.xray_bin()
        http_port = ProxyManager._free_port()
        socks_port = ProxyManager._free_port()

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
            )
            ready = False
            for _ in range(30):
                try:
                    s = socket.create_connection(("127.0.0.1", http_port), timeout=0.5)
                    s.close()
                    ready = True
                    break
                except (OSError, ConnectionRefusedError):
                    time.sleep(0.1)
            if not ready:
                return False, 0
            return ProxyManager._probe(http_port, timeout)
        except Exception as e:
            add_log("ERROR", f"VLESS test failed: {e}")
            return False, 0
        finally:
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    try:
                        proc.kill()
                        proc.wait(timeout=3)
                    except Exception:
                        pass
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

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
                "UPDATE proxies SET status='failed', latency=?, latency_vless=?, failed_since=COALESCE(failed_since, ?) WHERE id=?",
                (lat_vless, lat_vless, now, pid),
            )

    def _apply_with_throttle(self, interval=3.0):
        with self._apply_lock:
            now = time.time()
            if now - self._last_apply_time >= interval:
                from .xray_configurator import xray_configurator

                xray_configurator.apply_all()
                self._last_apply_time = now

    def _record_completion(self, label):
        self.progress.update(
            last_completed=moscow_str(),
            last_label=label,
            last_ok=self.progress["ok"],
            last_total=self.progress["total"],
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
            from .xray_configurator import xray_configurator

            xray_configurator.apply_all()

    # ─── Parallel batch testing ───

    def _test_one(self, r, timeout):
        ok, lat = self.test_vless_real(r["link"], timeout=timeout)
        self._update_vless_status(r["id"], ok, lat if ok else 0)
        with self._progress_lock:
            self.progress["done"] += 1
            if ok:
                self.progress["ok"] += 1
        if ok:
            self._apply_with_throttle()
        add_log(
            "INFO",
            f"VLESS test proxy #{r['id']} -> {'working' if ok else 'failed'} ({lat}ms)",
        )
        return r["id"], ok

    def _run_batch(self, rows, label, timeout, workers=5):
        if not rows:
            return
        self.progress.update(running=True, total=len(rows), done=0, ok=0, label=label)
        try:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(self._test_one, r, timeout): r for r in rows}
                for f in as_completed(futures):
                    pass
            from .utils import enrich_all_unknown_countries

            enrich_all_unknown_countries()
            from .xray_configurator import xray_configurator

            xray_configurator.apply_all(blocking=True)
            add_log(
                "INFO",
                f"VLESS {label}: {self.progress['ok']}/{self.progress['total']} ok — {moscow_str()}",
            )
        finally:
            self._record_completion(label)

    def test_all_vless(self):
        rows = db_q("SELECT id, link FROM proxies")
        if not rows:
            add_log("WARN", "Test all VLESS: no proxies to test")
            return
        self._run_batch(rows, "all", 3)

    def batch_test_vless(self, rows):
        self._run_batch(rows, "batch-test", 3)

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
        last_vless = 0.0
        while True:
            time.sleep(Settings.check_interval())
            from .xray_configurator import xray_configurator

            xray_configurator.apply_all()
            now = time.time()
            if now - last_vless >= Settings.vless_interval() and not self._vless_busy:
                last_vless = now
                threading.Thread(target=self._run_vless_chain, daemon=True).start()
                add_log("INFO", "BG VLESS chain started")

    def _run_vless_chain(self):
        try:
            # Реимпорт из всех источников
            src_list = db_q("SELECT id, url FROM sources")
            for src in src_list:
                import_from_url(src["url"], source_id=src["id"])

            from .utils import enrich_all_unknown_countries

            enrich_all_unknown_countries()

            src_rows = db_q(
                "SELECT id, link FROM proxies WHERE status='working' AND source_id IS NOT NULL"
            )
            if src_rows:
                add_log("INFO", f"VLESS source-only: {len(src_rows)} proxies")
                self._bg_vless_batch(src_rows, "source-only")

            all_rows = db_q("SELECT id, link FROM proxies WHERE status='working'")
            if all_rows:
                add_log("INFO", f"VLESS all: {len(all_rows)} proxies")
                self._bg_vless_batch(all_rows, "all")

            from .xray_configurator import xray_configurator

            xray_configurator.apply_all()
            add_log("INFO", "VLESS chain completed")
        except Exception as e:
            add_log("ERROR", f"VLESS chain crashed: {e}")
        finally:
            self._vless_busy = False


proxy_manager = ProxyManager()
