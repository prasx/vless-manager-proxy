"""Управление прокси: тестирование, обновление статуса, фоновые задачи."""

import json
import os
import socket
import subprocess
import tempfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .db import db_q, Settings
from .utils import add_log, now_utc, enrich_country, enrich_all_unknown_countries
from .importer import import_from_url
from .vless import parse_vless, stream_settings
from config import (
    CHECK_INTERVAL, REIMPORT_CYCLES, TEST_WORKERS,
    VLESS_BATCH_SIZE, VLESS_PER_PROXY_TIMEOUT,
    VLESS_CHECK_WORKING, VLESS_CHECK_ALL,
    SOCKS_PORT, HTTP_PORT, API_PORT, API_LISTEN, PROBE_INTERVAL,
)

_TEST_WORKERS = TEST_WORKERS


class ProxyManager:
    """Тестирование прокси, обновление статусов, фоновый циклический чекер."""

    def __init__(self):
        """Инициализирует флаг блокировки параллельного VLESS-теста."""
        self._vless_busy = False

    @staticmethod
    def _free_port():
        """Находит свободный порт."""
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    @staticmethod
    def check_host(host, port, timeout=5):
        """Проверяет доступность хоста:порта через TCP-соединение."""
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.close()
            return True
        except Exception:
            return False

    def test_proxy(self, link):
        """Тестирует один прокси: возвращает (ok: bool, latency_ms: int)."""
        ok, lat = False, 0
        parsed = parse_vless(link)
        if parsed:
            start = time.time()
            ok = self.check_host(parsed["host"], parsed["port"])
            lat = int((time.time() - start) * 1000) if ok else 0
        return ok, lat

    def test_vless_real(self, link, timeout=10):
        """Реальное тестирование VLESS через Xray. Возвращает (ok, latency_ms)."""
        xbin = Settings.xray_bin()
        if not Path(xbin).is_file():
            add_log("ERROR", f"VLESS test: xray binary not found at {xbin}")
            return False, 0

        parsed = parse_vless(link)
        if not parsed:
            return False, 0

        http_port = self._free_port()
        socks_port = self._free_port()

        config = {
            "log": {"loglevel": "none"},
            "inbounds": [
                {"port": socks_port, "listen": "127.0.0.1", "protocol": "socks",
                 "settings": {"udp": True}, "tag": "socks-in"},
                {"port": http_port, "listen": "127.0.0.1", "protocol": "http",
                 "settings": {}, "tag": "http-in"},
            ],
            "outbounds": [{
                "protocol": "vless", "tag": "proxy",
                "settings": {"vnext": [{
                    "address": parsed["server"], "port": parsed["port"],
                    "users": [{"id": parsed["uid"], "encryption": "none"}],
                }]},
                "streamSettings": stream_settings(parsed),
            }],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [{"type": "field", "inboundTag": ["socks-in", "http-in"], "outboundTag": "proxy"}],
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
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            ready = False
            for _ in range(50):
                try:
                    s = socket.create_connection(("127.0.0.1", http_port), timeout=0.5)
                    s.close()
                    ready = True
                    break
                except (OSError, ConnectionRefusedError):
                    time.sleep(0.1)
            if not ready:
                return False, 0

            probe_url = Settings.probe_url()
            proxy_url = f"http://127.0.0.1:{http_port}"
            proxy_handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
            opener = urllib.request.build_opener(proxy_handler)

            req_start = time.time()
            try:
                resp = opener.open(probe_url, timeout=timeout)
                ok = resp.status == 204
                lat = int((time.time() - req_start) * 1000)
            except Exception as e:
                add_log("DEBUG", f"VLESS test probe failed for {link[:50]}: {e}")
                ok, lat = False, 0
            return ok, lat
        except Exception as e:
            add_log("ERROR", f"VLESS real test failed: {e}")
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

    @staticmethod
    def _update_tcp_status(pid, ok, lat):
        """Обновляет статус, latency, last_checked и failed_since в БД (TCP ping)."""
        now = now_utc()
        if ok:
            db_q("UPDATE proxies SET status='working', latency=?, last_checked=?, failed_since=NULL WHERE id=?",
                 (lat, now, pid))
        else:
            db_q("UPDATE proxies SET status='failed', latency=?, last_checked=?, failed_since=COALESCE(failed_since, ?) WHERE id=?",
                 (lat, now, now, pid))

    @staticmethod
    def _update_vless_status(pid, ok, lat_vless):
        """Обновляет только status и latency_vless (не трогает TCP latency)."""
        now = now_utc()
        if ok:
            db_q("UPDATE proxies SET status='working', latency_vless=?, last_checked=?, failed_since=NULL WHERE id=?",
                 (lat_vless, now, pid))
        else:
            db_q("UPDATE proxies SET status='failed', latency_vless=?, last_checked=?, failed_since=COALESCE(failed_since, ?) WHERE id=?",
                 (lat_vless, now, now, pid))

    def test_and_update_vless(self, link):
        """Тестирует прокси через реальный VLESS и применяет конфиг."""
        ok, lat = self.test_vless_real(link)
        row = db_q("SELECT id FROM proxies WHERE link=?", (link,))
        if row:
            self._update_vless_status(row[0]["id"], ok, lat if ok else 0)
            add_log("INFO", f"VLESS test {link[:50]} -> {'working' if ok else 'failed'} ({lat}ms)")
            from .xray_configurator import xray_configurator
            xray_configurator.apply_all()

    def _check_one_tcp(self, row):
        """Проверяет один прокси (для параллельного запуска). Возвращает (id, host, country, ok)."""
        ok, lat = self.test_proxy(row["link"])
        self._update_tcp_status(row["id"], ok, lat)
        return row["id"], row["host"], row["country"], ok

    def test_all(self):
        """Тестирует все прокси из БД параллельно (TCP ping) и применяет конфиг."""
        rows = db_q("SELECT id, link, host, country FROM proxies")
        if not rows:
            add_log("WARN", "Test all: no proxies to test")
            return
        ok_count = 0
        with ThreadPoolExecutor(max_workers=_TEST_WORKERS) as pool:
            futures = {pool.submit(self._check_one_tcp, dict(r)): r for r in rows}
            for fut in as_completed(futures):
                try:
                    pid, host, country, ok = fut.result()
                    if ok:
                        ok_count += 1
                    if not country:
                        enrich_country(pid, host)
                except Exception as e:
                    add_log("WARN", f"Batch TCP test future failed: {e}")
        from .xray_configurator import xray_configurator
        xray_configurator.apply_all()
        add_log("INFO", f"Test all completed: {ok_count} working ({len(rows)} total)")

    def test_all_vless(self):
        """Тестирует все прокси через реальный VLESS (последовательно, один за другим)."""
        rows = db_q("SELECT id, link FROM proxies")
        if not rows:
            add_log("WARN", "Test all VLESS: no proxies to test")
            return
        ok_count = 0
        for r in rows:
            ok, lat = self.test_vless_real(r["link"])
            self._update_vless_status(r["id"], ok, lat if ok else 0)
            if ok:
                ok_count += 1
            add_log("INFO", f"VLESS test proxy #{r['id']} -> {'working' if ok else 'failed'} ({lat}ms)")
        from .xray_configurator import xray_configurator
        xray_configurator.apply_all()
        add_log("INFO", f"Test all VLESS completed: {ok_count}/{len(rows)} working")

    def batch_test_tcp(self, rows):
        """Батч-тест TCP для списка прокси (из api batch-test)."""
        for r in rows:
            ok, lat = self.test_proxy(r["link"])
            self._update_tcp_status(r["id"], ok, lat)
        from .xray_configurator import xray_configurator
        xray_configurator.apply_all()
        add_log("INFO", f"Batch test completed for {len(rows)} proxies")

    def batch_test_vless(self, rows):
        """Батч-тест VLESS прокси через реальный запуск Xray."""
        ok_count = 0
        for r in rows:
            ok, lat = self.test_vless_real(r["link"])
            self._update_vless_status(r["id"], ok, lat if ok else 0)
            if ok:
                ok_count += 1
            add_log("INFO", f"VLESS test proxy #{r['id']} -> {'working' if ok else 'failed'} ({lat}ms)")
        from .xray_configurator import xray_configurator
        xray_configurator.apply_all()
        add_log("INFO", f"VLESS real test completed: {ok_count}/{len(rows)} working")

    @staticmethod
    def reimport_all_sources():
        """Импортирует прокси из всех источников."""
        rows = db_q("SELECT id, url FROM sources")
        total = 0
        for r in rows:
            added = import_from_url(r["url"])
            db_q("UPDATE sources SET last_import=? WHERE id=?", (now_utc(), r["id"]))
            total += added
        if total:
            add_log("INFO", f"Hourly re-import: {total} new proxies")

    def background_checker(self):
        """Циклический TCP/VLESS-чекер всех прокси, переимпорт источников.

        - Каждый цикл: TCP всех прокси
        - Каждые 10 циклов (~10 мин): VLESS-тест рабочих VLESS-прокси
        - Каждые 60 циклов (~1 час): VLESS-тест ВСЕХ прокси + переимпорт
        """
        cycle = 0
        while True:
            time.sleep(CHECK_INTERVAL)
            cycle += 1

            rows = db_q("SELECT id, link, host, country FROM proxies")
            if not rows:
                if cycle % REIMPORT_CYCLES == 0:
                    self.reimport_all_sources()
                continue

            tcp_ok = 0
            with ThreadPoolExecutor(max_workers=_TEST_WORKERS) as pool:
                futures = {pool.submit(self._check_one_tcp, dict(r)): r for r in rows}
                for fut in as_completed(futures):
                    try:
                        pid, host, country, ok = fut.result()
                        if ok:
                            tcp_ok += 1
                        if not country:
                            enrich_country(pid, host)
                    except Exception as e:
                        add_log("WARN", f"BG check future failed: {e}")
            add_log("INFO", f"BG TCP: {tcp_ok}/{len(rows)} working")

            if not self._vless_busy:
                # Каждые VLESS_CHECK_ALL циклов — тест ВСЕХ TCP-рабочих прокси
                if cycle % VLESS_CHECK_ALL == 0:
                    vless_rows = db_q("SELECT id, link FROM proxies WHERE status='working'")
                    label = "all"
                # Каждые VLESS_CHECK_WORKING циклов — тест только рабочих VLESS
                elif cycle % VLESS_CHECK_WORKING == 0:
                    vless_rows = db_q(
                        "SELECT id, link FROM proxies WHERE latency_vless > 0 ORDER BY latency ASC",
                    )
                    label = "working"
                else:
                    vless_rows = []

                if vless_rows:
                    self._vless_busy = True
                    ok_count = 0
                    for r in vless_rows:
                        ok, lat = self.test_vless_real(r["link"], timeout=VLESS_PER_PROXY_TIMEOUT)
                        self._update_vless_status(r["id"], ok, lat if ok else 0)
                        if ok:
                            ok_count += 1
                    self._vless_busy = False
                    add_log("INFO", f"BG VLESS ({label}): {ok_count}/{len(vless_rows)} ok")

            enrich_all_unknown_countries()
            from .xray_configurator import xray_configurator
            xray_configurator.apply_all()

            if cycle % REIMPORT_CYCLES == 0:
                self.reimport_all_sources()
                add_log("INFO", "Hourly reimport completed")


proxy_manager = ProxyManager()
