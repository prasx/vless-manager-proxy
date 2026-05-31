"""Тестирование VLESS прокси: проверка доступности, обновление статуса."""

import json
import os
import socket
import subprocess
import tempfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .db import db_q, xray_bin
from .utils import add_log, now_utc, enrich_country
from .vless import parse_vless, stream_settings
from .xray_config import apply_all_proxies
from config import TEST_WORKERS

_TEST_PROBE_URL = "http://www.gstatic.com/generate_204"


def _free_port():
    """Находит свободный порт."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def check_proxy_via_curl(host, port, timeout=5):
    """Проверяет доступность хоста:порта через TCP-соединение."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def test_proxy(link):
    """Тестирует один прокси: возвращает (ok: bool, latency_ms: int)."""
    parsed = parse_vless(link)
    if not parsed:
        return False, 0
    start = time.time()
    ok = check_proxy_via_curl(parsed["host"], parsed["port"])
    latency = int((time.time() - start) * 1000) if ok else 0
    return ok, latency


def test_vless_real(link, timeout=10):
    """Реальное тестирование VLESS через Xray.

    Запускает xray с данным прокси, делает HTTP-запрос через него,
    измеряет реальный пинг и проверяет валидность подключения.

    Возвращает (ok: bool, latency_ms: int).
    """
    xbin = xray_bin()
    if not Path(xbin).is_file():
        add_log("ERROR", f"VLESS test: xray binary not found at {xbin}")
        return False, 0

    parsed = parse_vless(link)
    if not parsed:
        return False, 0

    http_port = _free_port()
    socks_port = _free_port()

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
            [xray_bin(), "run", "-c", tmp_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
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

        proxy_url = f"http://127.0.0.1:{http_port}"
        proxy_handler = urllib.request.ProxyHandler(
            {"http": proxy_url, "https": proxy_url}
        )
        opener = urllib.request.build_opener(proxy_handler)

        req_start = time.time()
        try:
            resp = opener.open(_TEST_PROBE_URL, timeout=timeout)
            ok = resp.status == 204
            latency = int((time.time() - req_start) * 1000)
        except Exception:
            ok = False
            latency = 0

        return ok, latency
    except Exception:
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


def update_proxy_status(pid, ok, lat):
    """Обновляет статус, latency, last_checked и failed_since в БД (TCP ping)."""
    now = now_utc()
    if ok:
        db_q(
            "UPDATE proxies SET status='working', latency=?, last_checked=?, failed_since=NULL WHERE id=?",
            (lat, now, pid),
        )
    else:
        db_q(
            "UPDATE proxies SET status='failed', latency=?, last_checked=?, failed_since=COALESCE(failed_since, ?) WHERE id=?",
            (lat, now, now, pid),
        )


def update_vless_status(pid, ok, lat_vless):
    """Обновляет только status и latency_vless (не трогает TCP latency)."""
    now = now_utc()
    if ok:
        db_q(
            "UPDATE proxies SET status='working', latency_vless=?, last_checked=?, failed_since=NULL WHERE id=?",
            (lat_vless, now, pid),
        )
    else:
        db_q(
            "UPDATE proxies SET status='failed', latency_vless=?, last_checked=?, failed_since=COALESCE(failed_since, ?) WHERE id=?",
            (lat_vless, now, now, pid),
        )


def _check_one(row):
    """Проверяет один прокси (для параллельного запуска). Возвращает (id, host, country, ok)."""
    ok, lat = test_proxy(row["link"])
    update_proxy_status(row["id"], ok, lat)
    return row["id"], row["host"], row["country"], ok


def _check_one_vless(row):
    """Проверяет один VLESS прокси реальным тестом (через Xray). Возвращает (id, ok)."""
    ok, lat = test_vless_real(row["link"])
    update_vless_status(row["id"], ok, lat if ok else 0)
    return row["id"], ok


def test_and_update(link):
    """Тестирует прокси по ссылке (TCP) и при успехе применяет конфиг."""
    row = db_q("SELECT id FROM proxies WHERE link=?", (link,))
    if not row:
        return
    ok, lat = test_proxy(link)
    update_proxy_status(row[0]["id"], ok, lat)
    add_log("INFO", f"TCP test {link[:50]} → {'working' if ok else 'failed'} ({lat}ms)")
    if ok:
        apply_all_proxies()


def test_and_update_vless(link):
    """Тестирует прокси через реальный VLESS и применяет конфиг."""
    row = db_q("SELECT id FROM proxies WHERE link=?", (link,))
    if not row:
        return
    ok, lat = test_vless_real(link)
    update_vless_status(row[0]["id"], ok, lat if ok else 0)
    add_log(
        "INFO",
        f"VLESS test {link[:50]} → {'working' if ok else 'failed'} ({lat}ms)",
    )
    apply_all_proxies()


def update_all():
    """Тестирует все прокси из БД параллельно (TCP ping) и применяет конфиг."""
    rows = db_q("SELECT id, link, host, country FROM proxies")
    if not rows:
        add_log("WARN", "Test all: no proxies to test")
        return
    ok_count = 0
    fail_count = 0
    with ThreadPoolExecutor(max_workers=TEST_WORKERS) as pool:
        futures = {pool.submit(_check_one, dict(r)): r for r in rows}
        for fut in as_completed(futures):
            try:
                pid, host, country, ok = fut.result()
                if ok:
                    ok_count += 1
                else:
                    fail_count += 1
                if not country:
                    enrich_country(pid, host)
            except Exception:
                pass
    apply_all_proxies()
    add_log(
        "INFO",
        f"Test all completed: {ok_count} working, {fail_count} failed ({len(rows)} total)",
    )


def update_all_vless():
    """Тестирует все прокси через реальный VLESS (последовательно, один за другим)."""
    rows = db_q("SELECT id, link FROM proxies")
    if not rows:
        add_log("WARN", "Test all VLESS: no proxies to test")
        return
    ok_count = 0
    for r in rows:
        ok, lat = test_vless_real(r["link"])
        update_vless_status(r["id"], ok, lat if ok else 0)
        if ok:
            ok_count += 1
        add_log(
            "INFO",
            f"VLESS test proxy #{r['id']} → {'working' if ok else 'failed'} ({lat}ms)",
        )
    apply_all_proxies()
    add_log(
        "INFO",
        f"Test all VLESS completed: {ok_count}/{len(rows)} working",
    )
