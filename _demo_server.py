"""Демо-БД для скриншотов README: синтетические профили, без данных владельца."""
import random
import tempfile
import threading
import uuid
from datetime import timedelta
from pathlib import Path

import app.db as db
from app import create_app
from app.db import db_q, init_db, Settings
from app.utils import now_utc

tmp = Path(tempfile.mkdtemp(prefix="vless-readme-"))
dst = tmp / "demo.db"
db.DATABASE = dst
db._tls = threading.local()
init_db()
Settings.invalidate()
Settings.set("blocked_countries", "")
Settings.set("max_active_proxies", "30")

now = now_utc()
random.seed(4)


def fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")


sources = [
    ("EU Premium", "https://example.com/eu-premium.txt", 42, 21, 15, "ok", 42, 0, 42),
    ("US Backbone", "https://example.com/us-backbone.txt", 30, 9, 6, "ok", 30, 0, 30),
    ("Asia Mix", "https://example.com/asia-mix.txt", 50, 4, 2, "ok", 44, 6, 50),
    ("Public Free", "https://example.com/public-free.txt", 160, 2, 0, "ok", 160, 0, 160),
    ("Old Mirror", "https://example.com/old-mirror.txt", 0, 0, 0, "network_error", 0, 0, 0),
]
source_ids = []
for name, url, total, working, measured, status, added, dupes, parsed in sources:
    db_q(
        "INSERT INTO sources (name, url, type, created_at, last_import, last_status, last_error, "
        "last_added, last_duplicates, last_parsed) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (name, url, "url", fmt(now - timedelta(days=6)), fmt(now - timedelta(minutes=25)),
         status, "таймаут соединения" if status != "ok" else "", added, dupes, parsed),
    )
    source_ids.append(db_q("SELECT id FROM sources ORDER BY id DESC LIMIT 1")[0]["id"])

countries = ["DE", "NL", "US", "SG", "JP", "FR", "GB", "PL", "FI", "SE"]
for sid, (name, _url, total, working, measured, _status, _added, _dupes, _parsed) in zip(source_ids, sources):
    for i in range(total):
        host = f"{name.split()[0].lower()}-{i + 1:02d}.example.net"
        link = (
            f"vless://{uuid.uuid4()}@{host}:443?security=tls&type=tcp&sni={host}"
            f"#{countries[(sid + i) % len(countries)]}"
        )
        is_working = i < working
        is_measured = is_working and i < measured
        ts = now - timedelta(minutes=random.randint(2, 55))
        avg = random.choice([9_500, 14_000, 22_000, 38_000, 57_000, 76_000, 91_000]) if is_measured else 0
        peak = int(avg * random.uniform(1.08, 1.22)) if is_measured else 0
        db_q(
            "INSERT OR IGNORE INTO proxies "
            "(link, host, port, country, status, security, added_at, last_test_at, last_ok_at, "
            "latency, latency_vless, speed_kbps, speed_max_kbps, source_id, fail_count, next_test_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                link, host, 443, countries[(sid + i) % len(countries)],
                "working" if is_working else "failed",
                "tls", fmt(now - timedelta(days=2)),
                fmt(ts), fmt(ts) if is_working else None,
                random.randint(90, 900) if is_working else 0,
                random.randint(90, 900) if is_working else 0,
                avg, peak, sid,
                0 if is_working else random.randint(1, 6),
                None if is_working else fmt(now - timedelta(minutes=30)),
            ),
        )

from app.xray_configurator import xray_configurator

xray_configurator.api_ok = lambda: True
node_tags = [f"node{i}" for i in range(1, 31)]
stats = "\n".join(f"outbound>>>{tag}>>>traffic>>>downlink 1048576" for tag in node_tags)
xray_configurator._cached_statsquery = lambda ttl=10: (0, stats)
xray_configurator.diagnose = lambda: {
    "systemd_active": True,
    "config_mismatch": False,
    "ports": {"1080": "listening", "1081": "listening", "10085": "listening"},
    "manager_config_path": "/etc/xray/config.json",
    "systemd_config_path": "/etc/xray/config.json",
    "config_inbounds": [],
    "socks_in_config": True,
    "proxy_listen": "0.0.0.0",
}

app = create_app()
app.run(host="127.0.0.1", port=5078, debug=False, use_reloader=False, threaded=True)
