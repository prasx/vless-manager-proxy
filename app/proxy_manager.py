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
from .utils import add_log, now_utc, moscow_str, enrich_country, enrich_all_unknown_countries
from .importer import import_from_url
from .vless import parse_vless, stream_settings


class ProxyManager:
    """Тестирование прокси, обновление статусов, фоновый циклический чекер."""

    def __init__(self):
        """Инициализирует флаг блокировки параллельного VLESS-теста."""
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
        """Обновляет latency_vless, не трогая status (TCP-статус первичен)."""
        now = now_utc()
        db_q("UPDATE proxies SET latency_vless=?, last_checked=? WHERE id=?",
             (lat_vless, now, pid))

    def _record_completion(self, label):
        """Записывает в прогресс время завершения теста."""
        self.progress.update(
            last_completed=moscow_str(),
            last_label=label,
            last_ok=self.progress["ok"],
            last_total=self.progress["total"],
        )
        self.progress["running"] = False

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
        """Тестирует все прокси (TCP ping) параллельно."""
        rows = db_q("SELECT id, link, host, country FROM proxies")
        if not rows:
            add_log("WARN", "Test all: no proxies to test")
            return
        self.progress.update(running=True, total=len(rows), done=0, ok=0, label="tcp")
        ok_count = 0
        try:
            with ThreadPoolExecutor(max_workers=Settings.test_workers()) as pool:
                futures = {pool.submit(self._check_one_tcp, dict(r)): r for r in rows}
                for fut in as_completed(futures):
                    try:
                        pid, host, country, ok = fut.result()
                        self.progress["done"] += 1
                        if ok:
                            ok_count += 1
                            self.progress["ok"] += 1
                        if not country:
                            enrich_country(pid, host)
                    except Exception as e:
                        self.progress["done"] += 1
                        add_log("WARN", f"Batch TCP test future failed: {e}")
            from .xray_configurator import xray_configurator
            xray_configurator.apply_all()
            add_log("INFO", f"Test all completed: {ok_count} working ({len(rows)} total)")
        finally:
            self._record_completion("tcp")

    def test_all_vless(self):
        """Тестирует все прокси через реальный VLESS (последовательно, один за другим)."""
        rows = db_q("SELECT id, link FROM proxies")
        if not rows:
            add_log("WARN", "Test all VLESS: no proxies to test")
            return
        self.progress.update(running=True, total=len(rows), done=0, ok=0, label="all")
        try:
            for r in rows:
                ok, lat = self.test_vless_real(r["link"])
                self._update_vless_status(r["id"], ok, lat if ok else 0)
                self.progress["done"] += 1
                if ok:
                    self.progress["ok"] += 1
                add_log("INFO", f"VLESS test proxy #{r['id']} -> {'working' if ok else 'failed'} ({lat}ms)")
            from .xray_configurator import xray_configurator
            xray_configurator.apply_all()
            add_log("INFO", f"Test all VLESS completed: {self.progress['ok']}/{self.progress['total']} working")
        finally:
            self._record_completion("all")

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
        self.progress.update(running=True, total=len(rows), done=0, ok=0, label="batch-test")
        try:
            for r in rows:
                ok, lat = self.test_vless_real(r["link"])
                self._update_vless_status(r["id"], ok, lat if ok else 0)
                self.progress["done"] += 1
                if ok:
                    self.progress["ok"] += 1
                add_log("INFO", f"VLESS test proxy #{r['id']} -> {'working' if ok else 'failed'} ({lat}ms)")
            from .xray_configurator import xray_configurator
            xray_configurator.apply_all()
            add_log("INFO", f"VLESS real test completed: {self.progress['ok']}/{self.progress['total']} working")
        finally:
            self._record_completion("batch-test")

    def _bg_vless_batch(self, rows, label):
        """Фоновый VLESS-тест пачки прокси (запускается в отдельном потоке)."""
        self.progress.update(running=True, total=len(rows), done=0, ok=0, label=label)
        try:
            for r in rows:
                ok, lat = self.test_vless_real(r["link"], timeout=Settings.vless_per_proxy_timeout())
                self._update_vless_status(r["id"], ok, lat if ok else 0)
                self.progress["done"] += 1
                if ok:
                    self.progress["ok"] += 1
                if self.progress["done"] % 10 == 0:
                    add_log("DEBUG", f"BG VLESS ({label}): {self.progress['ok']}/{self.progress['done']} ok so far")
            add_log("INFO", f"BG VLESS ({label}): {self.progress['ok']}/{self.progress['total']} ok — {moscow_str()}")
        except Exception as e:
            add_log("ERROR", f"BG VLESS ({label}) crashed: {e}")
        finally:
            self._vless_busy = False
            self._record_completion(label)

    def background_checker(self):
        """Циклический TCP/VLESS-чекер всех прокси, переимпорт источников.

        - Каждый цикл: TCP всех прокси (параллельно)
        - VLESS-тест рабочих/всех прокси в фоновом потоке по расписанию
        - apply_all() вызывается сразу после TCP, не ждёт VLESS
        """
        cycle = 0
        while True:
            time.sleep(Settings.check_interval())
            cycle += 1

            rows = db_q("SELECT id, link, host, country FROM proxies")
            if not rows:
                if cycle % Settings.reimport_cycles() == 0:
                    self.reimport_all_sources()
                continue

            tcp_ok = 0
            with ThreadPoolExecutor(max_workers=Settings.test_workers()) as pool:
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
                if cycle % Settings.vless_check_all() == 0:
                    vless_rows = db_q("SELECT id, link FROM proxies WHERE status='working'")
                    label = "all"
                elif cycle % Settings.vless_check_working() == 0:
                    vless_rows = db_q(
                        "SELECT id, link FROM proxies WHERE latency_vless > 0 ORDER BY latency ASC",
                    )
                    label = "working"
                else:
                    vless_rows = []

                if vless_rows:
                    self._vless_busy = True
                    threading.Thread(
                        target=self._bg_vless_batch,
                        args=(vless_rows, label),
                        daemon=True,
                    ).start()

            enrich_all_unknown_countries()
            from .xray_configurator import xray_configurator
            xray_configurator.apply_all()

            if cycle % Settings.reimport_cycles() == 0:
                self.reimport_all_sources()
                add_log("INFO", "Hourly reimport completed")


proxy_manager = ProxyManager()
