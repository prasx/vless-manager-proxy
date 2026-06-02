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
        self._failed_cycle = 0  # счётчик фоновых циклов для ретеста failed
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

    # ─── Xray proxy helpers ───

    @staticmethod
    def _xray_config(parsed, http_port, socks_port):
        """Собирает конфиг Xray для одного прокси."""
        config = {
            "log": {"loglevel": "none"},
            "inbounds": [
                {"port": socks_port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": True}, "tag": "socks-in"},
                {"port": http_port, "listen": "127.0.0.1", "protocol": "http", "settings": {}, "tag": "http-in"},
            ],
            "outbounds": [{
                "protocol": "vless", "tag": "proxy",
                "settings": {"vnext": [{"address": parsed["server"], "port": parsed["port"], "users": [{"id": parsed["uid"], "encryption": "none"}]}]},
                "streamSettings": stream_settings(parsed),
            }],
            "routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "inboundTag": ["socks-in", "http-in"], "outboundTag": "proxy"}]},
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
            proc = subprocess.Popen([xbin, "run", "-c", tmp_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(30):
                try:
                    s = socket.create_connection(("127.0.0.1", http_port), timeout=0.5)
                    s.close()
                    return proc, tmp_path, http_port
                except (OSError, ConnectionRefusedError):
                    time.sleep(0.1)
        except Exception:
            pass
        ProxyManager._stop_xray(proc, tmp_path)
        return None, None, None

    @staticmethod
    def _stop_xray(proc, tmp_path):
        """Останавливает Xray и удаляет временный файл."""
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
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

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
        """Скачивает speed-test файл через HTTP-прокси, возвращает kbps."""
        url = Settings.get("speed_test_url", "http://proof.ovh.net/files/100Kb.dat")
        proxy_url = f"http://127.0.0.1:{http_port}"
        proxy_handler = urllib.request.ProxyHandler(
            {"http": proxy_url, "https": proxy_url}
        )
        opener = urllib.request.build_opener(proxy_handler)
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            })
            req_start = time.time()
            resp = opener.open(req, timeout=timeout)
            total = 0
            buf = resp.read(65536)
            while buf:
                total += len(buf)
                buf = resp.read(65536)
            elapsed = time.time() - req_start
            if elapsed > 0 and total > 0:
                return int((total * 8) / (elapsed * 1000))
        except Exception as e:
            add_log("DEBUG", f"Speed measure failed: {e}")
        return 0

    def _run_speed_test_for_top(self):
        """После VLESS-теста замеряет скорость для top-N быстрых прокси."""
        if Settings.get("speed_test_enabled", "true") != "true":
            return
        max_count = int(Settings.get("speed_test_max", "20"))
        rows = db_q(
            "SELECT id, link FROM proxies WHERE status='working' AND latency_vless > 0 ORDER BY latency_vless LIMIT ?",
            (max_count,),
        )
        if not rows:
            return
        add_log("INFO", f"Speed test: {len(rows)} proxies")
        self.progress.update(running=True, total=len(rows), done=0, ok=0, label="Speed test")
        changed = False
        for r in rows:
            kbps = self._test_speed_single(r["link"])
            db_q("UPDATE proxies SET speed_kbps=? WHERE id=?", (kbps, r["id"]))
            if kbps:
                changed = True
            with self._progress_lock:
                self.progress["done"] += 1
                if kbps:
                    self.progress["ok"] += 1
            add_log("INFO", f"Speed #{r['id']}: {kbps} kbps")
        if changed:
            from .xray_configurator import xray_configurator
            xray_configurator.apply_all(blocking=True)
            add_log("INFO", "Config reapplied after speed test")

    def _test_speed_single(self, link, timeout=15):
        """Запускает Xray для одного прокси, меряет скорость, возвращает kbps."""
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
                "UPDATE proxies SET status='failed', latency=?, latency_vless=?, failed_since=COALESCE(failed_since, ?) WHERE id=?",
                (lat_vless, lat_vless, now, pid),
            )

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
        add_log(
            "INFO",
            f"VLESS test proxy #{r['id']} -> {'working' if ok else 'failed'} ({lat}ms)",
        )
        return r["id"], ok

    def _run_batch(self, rows, label, timeout, workers=5):
        if not rows:
            return
        self.progress.update(running=True, total=len(rows), done=0, ok=0, label=label)
        vless_ok = 0
        vless_total = 0
        try:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(self._test_one, r, timeout): r for r in rows}
                for f in as_completed(futures):
                    pass
            vless_ok = self.progress["ok"]
            vless_total = self.progress["total"]
            from .utils import enrich_all_unknown_countries

            enrich_all_unknown_countries()
            from .xray_configurator import xray_configurator

            xray_configurator.apply_all(blocking=True)
            add_log(
                "INFO",
                f"VLESS {label}: {vless_ok}/{vless_total} ok — {moscow_str()}",
            )

            # Speed test top-N после полного цикла
            if label in ("all", "batch-test"):
                self._run_speed_test_for_top()
        finally:
            if self.progress["label"] == "Speed test":
                # Показываем в last итог: VLESS + Speed
                self.progress.update(
                    last_completed=moscow_str(),
                    last_label=f"VLESS + Speed",
                    last_ok=vless_ok,
                    last_total=vless_total,
                )
                self.progress["running"] = False
            else:
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
            try:
                time.sleep(Settings.check_interval())
            except Exception:
                time.sleep(60)
            try:
                from .xray_configurator import xray_configurator

                xray_configurator.apply_all()
                now = time.time()
                if now - last_vless >= Settings.vless_interval() and not self._vless_busy:
                    last_vless = now
                    threading.Thread(target=self._run_vless_chain, daemon=True).start()
                    add_log("INFO", "BG VLESS chain started")
            except Exception as e:
                add_log("ERROR", f"Background checker crashed: {e}")

    def _run_vless_chain(self):
        try:
            # Реимпорт из всех источников
            src_list = db_q("SELECT id, url FROM sources")
            for src in src_list:
                import_from_url(src["url"], source_id=src["id"])

            from .utils import enrich_all_unknown_countries

            enrich_all_unknown_countries()

            # Тестируем source-only (из подписок)
            src_rows = db_q(
                "SELECT id, link FROM proxies WHERE status='working' AND source_id IS NOT NULL"
            )
            if src_rows:
                add_log("INFO", f"VLESS source-only: {len(src_rows)} proxies")
                self._bg_vless_batch(src_rows, "source-only")

            # Тестируем все working
            all_rows = db_q("SELECT id, link FROM proxies WHERE status='working'")
            if all_rows:
                add_log("INFO", f"VLESS all: {len(all_rows)} proxies")
                self._bg_vless_batch(all_rows, "all")

            # Каждый 3-й цикл — ретест failed прокси
            self._failed_cycle += 1
            if self._failed_cycle % 3 == 0:
                failed_rows = db_q(
                    "SELECT id, link FROM proxies WHERE status='failed'"
                )
                if failed_rows:
                    add_log(
                        "INFO",
                        f"VLESS retest failed: {len(failed_rows)} proxies",
                    )
                    self._bg_vless_batch(failed_rows, "retest-failed")

            from .xray_configurator import xray_configurator

            xray_configurator.apply_all()
            add_log("INFO", "VLESS chain completed")
        except Exception as e:
            add_log("ERROR", f"VLESS chain crashed: {e}")
        finally:
            self._vless_busy = False


proxy_manager = ProxyManager()
