#!/usr/bin/env python3
# VLESS Manager — Flask микросервис для управления VLESS прокси

import json, sqlite3, threading, time, urllib.request, re, subprocess, os, socket, tempfile
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False

BASE_DIR = Path(__file__).parent
DATABASE = BASE_DIR / "proxies.db"

_geo_cache: dict = {}
_geo_cache_lock = threading.Lock()

# ─────────────────────── Xray Daemon ───────────────────────


def xray_api_ok():
    try:
        r = subprocess.run(
            [xray_bin(), "api", "statsquery", "-s", "127.0.0.1:10085"],
            capture_output=True,
            timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def proxy_listen():
    """Address for SOCKS/HTTP inbounds. Use 0.0.0.0 to accept LAN clients."""
    return get_setting("proxy_listen", "0.0.0.0")


def _proxy_inbounds(listen):
    return [
        {
            "port": 1080,
            "listen": listen,
            "protocol": "socks",
            "settings": {"udp": True},
        },
        {"port": 1081, "listen": listen, "protocol": "http", "settings": {}},
    ]


def _apply_proxy_listen(cfg):
    """Set listen on SOCKS/HTTP inbounds; API inbound stays on 127.0.0.1."""
    listen = proxy_listen()
    for ib in cfg.get("inbounds", []):
        if ib.get("protocol") in ("socks", "http"):
            ib["listen"] = listen
    return cfg


def _inject_api(cfg):
    """Ensure the config dict has the API section, inbound, outbound, and routing rule."""
    _sanitize_outbounds(cfg)
    _apply_proxy_listen(cfg)
    cfg.setdefault(
        "api", {"tag": "api", "services": ["HandlerService", "RoutingService"]}
    )
    api_inbound = {
        "listen": "127.0.0.1",
        "port": 10085,
        "protocol": "dokodemo-door",
        "settings": {"address": "127.0.0.1"},
        "tag": "api",
    }
    if not any(ib.get("tag") == "api" for ib in cfg.get("inbounds", [])):
        cfg.setdefault("inbounds", []).append(api_inbound)
    api_outbound = {"protocol": "freedom", "tag": "api"}
    if not any(o.get("tag") == "api" for o in cfg.get("outbounds", [])):
        cfg.setdefault("outbounds", []).append(api_outbound)
    api_rule = {"inboundTag": ["api"], "outboundTag": "api"}
    rules = cfg.setdefault("routing", {}).setdefault("rules", [])
    if not any(r.get("outboundTag") == "api" for r in rules):
        rules.append(api_rule)
    _sanitize_outbounds(cfg)
    return cfg


def ensure_config():
    cfg = xray_config_path()
    if cfg.exists():
        try:
            data = json.loads(cfg.read_text())
            data = _inject_api(data)
            cfg.write_text(json.dumps(data, indent=2))
        except Exception:
            pass
    return cfg


# ─────────────────────── База ───────────────────────


def _get_conn():
    conn = sqlite3.connect(str(DATABASE), timeout=15)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _get_conn()
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS proxies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            link TEXT UNIQUE,
            host TEXT,
            port INTEGER,
            country TEXT,
            status TEXT DEFAULT 'pending',
            latency INTEGER DEFAULT 0,
            last_checked TIMESTAMP,
            added_at TIMESTAMP,
            failed_since TIMESTAMP,
            success_count INTEGER DEFAULT 0,
            fail_count INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            url TEXT UNIQUE,
            last_import TIMESTAMP,
            created_at TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP,
            level TEXT,
            message TEXT
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
    """)
    try:
        c.execute("ALTER TABLE proxies ADD COLUMN failed_since TIMESTAMP")
    except sqlite3.OperationalError:
        pass

    # default settings
    try:
        c.execute("ALTER TABLE proxies ADD COLUMN security TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass

    # backfill security for existing rows
    c.execute("SELECT id, link FROM proxies WHERE security IS NULL OR security = ''")
    for row in c.fetchall():
        parsed = parse_vless(row["link"])
        if parsed:
            sec = parsed.get("security", "none") or "none"
            c.execute("UPDATE proxies SET security=? WHERE id=?", (sec, row["id"]))
        else:
            c.execute("UPDATE proxies SET security='none' WHERE id=?", (row["id"],))

    defaults = {
        "xray_bin": "/usr/local/bin/xray",
        "xray_config_path": str(default_xray_config_path()),
        "xray_hot_reload": "false",
        "proxy_listen": "0.0.0.0",
    }

    for k, v in defaults.items():
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))
    conn.commit()
    conn.close()


_LOG_TRIM_EVERY = 500
_log_insert_count = 0
_log_count_lock = threading.Lock()


def add_log(level, message):
    global _log_insert_count
    conn = _get_conn()
    try:
        conn.execute(
            "INSERT INTO logs (timestamp, level, message) VALUES (?, ?, ?)",
            (datetime.now(), level, message),
        )
        conn.commit()
    finally:
        conn.close()
    with _log_count_lock:
        _log_insert_count += 1
        do_trim = _log_insert_count % _LOG_TRIM_EVERY == 0
    if do_trim:
        _trim_logs()


def _trim_logs(keep=2000):
    conn = _get_conn()
    try:
        conn.execute(
            "DELETE FROM logs WHERE id NOT IN (SELECT id FROM logs ORDER BY id DESC LIMIT ?)",
            (keep,),
        )
        conn.commit()
    finally:
        conn.close()


def db_q(sql, params=()):
    conn = _get_conn()
    try:
        c = conn.cursor()
        c.execute(sql, params)
        conn.commit()
        return c.fetchall()
    finally:
        conn.close()


# ─────────────────────── Settings ───────────────────────


def get_setting(key, default=""):
    rows = db_q("SELECT value FROM settings WHERE key=?", (key,))
    return rows[0]["value"] if rows else default


def set_setting(key, value):
    db_q("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))


def xray_bin():
    return get_setting("xray_bin", "xray")


def default_xray_config_path():
    etc = Path("/etc/xray/config.json")
    if etc.exists():
        return etc
    return BASE_DIR / "xray_config.json"


def detect_systemd_xray_config():
    try:
        r = subprocess.run(
            ["systemctl", "show", "xray", "-p", "ExecStart", "--value"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if r.returncode != 0:
            return None
        text = r.stdout.strip()
        for flag in ("-config", "-c"):
            if flag not in text:
                continue
            parts = text.replace("=", " ").split()
            for i, p in enumerate(parts):
                if p == flag and i + 1 < len(parts):
                    return parts[i + 1]
    except Exception:
        pass
    return None


def systemd_xray_active():
    try:
        r = subprocess.run(
            ["systemctl", "is-active", "xray"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        return r.stdout.strip() == "active"
    except Exception:
        return False


def _ss_listen(port):
    try:
        r = subprocess.run(["ss", "-lntp"], capture_output=True, text=True, timeout=3)
        for line in (r.stdout or "").splitlines():
            if f":{port}" in line:
                return line.strip()
    except Exception:
        pass
    return None


def _config_inbound_listeners(path=None):
    p = Path(path) if path else xray_config_path()
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text())
        return [
            {
                "protocol": ib.get("protocol"),
                "port": ib.get("port"),
                "listen": ib.get("listen"),
            }
            for ib in data.get("inbounds", [])
            if ib.get("protocol") in ("socks", "http")
        ]
    except Exception:
        return []


def xray_diagnose():
    mgr = str(xray_config_path().resolve())
    systemd_cfg = detect_systemd_xray_config()
    inbounds = _config_inbound_listeners()
    has_socks = any(
        ib.get("port") == 1080 and ib.get("protocol") == "socks" for ib in inbounds
    )
    return {
        "manager_config_path": mgr,
        "systemd_config_path": systemd_cfg,
        "config_mismatch": bool(systemd_cfg and systemd_cfg != mgr),
        "systemd_active": systemd_xray_active(),
        "config_inbounds": inbounds,
        "socks_in_config": has_socks,
        "ports": {str(p): _ss_listen(p) for p in (1080, 1081, 10085)},
        "proxy_listen": proxy_listen(),
    }


def xray_config_path():
    default_path = default_xray_config_path()
    configured = get_setting("xray_config_path", "")
    if not configured:
        return default_path

    p = Path(configured)
    try:
        if p.exists():
            return p
    except Exception:
        pass

    # If the DB contains a stale/incorrect absolute path (e.g. Windows path)
    # or the file was moved, fall back to the config inside the project folder.
    if default_path.exists() and str(default_path) != configured:
        try:
            set_setting("xray_config_path", str(default_path))
        except Exception:
            pass
    return default_path


# ─────────────────────── Парсинг VLESS ───────────────────────

_VALID_FLOWS = frozenset({"xtls-rprx-vision", "xtls-rprx-direct"})


def sanitize_flow(flow):
    """Strip remark/fragment accidentally merged into flow (common in subscription links)."""
    if not flow:
        return ""
    flow = unquote(str(flow)).split("#")[0].split("&")[0].strip()
    if flow in _VALID_FLOWS:
        return flow
    if flow.startswith("xtls-rprx-vision"):
        return "xtls-rprx-vision"
    if flow.startswith("xtls-rprx-direct"):
        return "xtls-rprx-direct"
    return ""


def sanitize_short_id(sid):
    """Reality shortId must be hex only; subscriptions often append #remark."""
    if not sid:
        return ""
    sid = unquote(str(sid)).split("#")[0].split("&")[0].strip()
    m = re.match(r"^([0-9a-fA-F]{1,16})", sid)
    return m.group(1) if m else ""


def _sanitize_outbounds(cfg):
    """Fix missing tags and polluted flow/shortId fields (breaks Xray 26+)."""
    used_tags = set()
    for i, ob in enumerate(cfg.get("outbounds", [])):
        tag = (ob.get("tag") or "").strip()
        proto = ob.get("protocol", "")
        if not tag:
            if proto == "vless":
                tag = "proxy"
            elif proto == "freedom":
                tag = (
                    "api"
                    if any(ib.get("tag") == "api" for ib in cfg.get("inbounds", []))
                    and "api" not in used_tags
                    and "direct" in used_tags
                    else "direct"
                )
            else:
                tag = f"outbound-{i}"
            ob["tag"] = tag
        base = ob["tag"]
        n = 1
        while ob["tag"] in used_tags:
            ob["tag"] = f"{base}-{n}"
            n += 1
        used_tags.add(ob["tag"])

        if proto != "vless":
            continue
        for vn in ob.get("settings", {}).get("vnext", []):
            for user in vn.get("users", []):
                if "flow" in user:
                    flow = sanitize_flow(user.get("flow"))
                    if flow:
                        user["flow"] = flow
                    else:
                        user.pop("flow", None)
        ss = ob.get("streamSettings") or {}
        rs = ss.get("realitySettings")
        if isinstance(rs, dict) and rs.get("shortId") is not None:
            rs["shortId"] = sanitize_short_id(rs["shortId"])
    return cfg


def _vless_param(parsed, *keys):
    for k in keys:
        v = parsed.get(k)
        if v:
            return v
    return ""


def parse_vless(link):
    link = link.strip()
    if not link.lower().startswith("vless://"):
        return None
    parsed = urlparse(link.replace("vless://", "https://", 1))
    uid, server, port = parsed.username, parsed.hostname, parsed.port
    if not uid or not server or port is None:
        return None
    result = {
        "uid": uid,
        "server": server,
        "host": server,
        "port": int(port),
        "link": link,
    }
    for k, vals in parse_qs(parsed.query, keep_blank_values=True).items():
        result[k] = unquote(vals[0]) if vals else ""
    # ?host= in VLESS is usually WS/HTTP Host header, not the dial address
    if result.get("host") != server:
        result["headerHost"] = result["host"]
    result["host"] = server
    result["server"] = server
    if "flow" in result:
        result["flow"] = sanitize_flow(result["flow"])
    if "sid" in result:
        result["sid"] = sanitize_short_id(result["sid"])
    fragment = unquote(parsed.fragment) if parsed.fragment else ""
    country_m = re.search(r"^([A-Z]{2})\b", fragment) or re.search(
        r"[#\s]([A-Z]{2})\b", fragment
    )
    result["country"] = country_m.group(1) if country_m else ""
    return result


# ─────────────────────── Определение страны ───────────────────────


def detect_country(host):
    with _geo_cache_lock:
        if host in _geo_cache:
            return _geo_cache[host]
    try:
        ip = socket.gethostbyname(host)
        url = f"http://ip-api.com/json/{ip}?fields=countryCode"
        with urllib.request.urlopen(url, timeout=3) as r:
            data = json.loads(r.read().decode())
        cc = data.get("countryCode", "")
        if cc:
            with _geo_cache_lock:
                _geo_cache[host] = cc
            return cc
    except Exception:
        pass
    return ""


def enrich_country(pid, host):
    cc = detect_country(host)
    if cc:
        db_q("UPDATE proxies SET country=? WHERE id=?", (cc, pid))
        return True
    return False


def enrich_all_unknown_countries():
    """Clean up long/invalid country names from old imports."""
    rows = db_q(
        "SELECT id, host FROM proxies WHERE country IS NULL OR country = '' OR length(country) > 2"
    )
    for r in rows:
        enrich_country(r["id"], r["host"])


# ─────────────────────── Проверка прокси ───────────────────────


def check_proxy_via_curl(host, port, timeout=5):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def test_proxy(link):
    parsed = parse_vless(link)
    if not parsed:
        return False, 0
    start = time.time()
    ok = check_proxy_via_curl(parsed["host"], parsed["port"])
    latency = int((time.time() - start) * 1000) if ok else 0
    return ok, latency


def update_proxy_status(pid, ok, lat):
    now = datetime.now()
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


# ─────────────────────── Xray Config ───────────────────────


def _reality_server_name(parsed):
    return (
        _vless_param(parsed, "sni", "serverName")
        or parsed.get("headerHost")
        or parsed["server"]
    )


def stream_settings(parsed):
    net = parsed.get("type", "tcp")
    sec = parsed.get("security", "none")
    s = {"network": net}
    hdr_host = parsed.get("headerHost") or _vless_param(parsed, "host")
    if net == "ws":
        ws = {}
        if parsed.get("path"):
            ws["path"] = parsed["path"]
        if hdr_host:
            ws["headers"] = {"Host": hdr_host}
        if ws:
            s["wsSettings"] = ws
    elif net == "grpc":
        g = {"multiMode": False}
        if parsed.get("serviceName"):
            g["serviceName"] = parsed["serviceName"]
        s["grpcSettings"] = g
    elif net == "kcp":
        k = {}
        if parsed.get("seed"):
            k["seed"] = parsed["seed"]
        if parsed.get("headerType"):
            k["header"] = {"type": parsed["headerType"]}
        s["kcpSettings"] = k
    elif net == "h2" or net == "http":
        h2 = {}
        if parsed.get("path"):
            h2["path"] = parsed["path"]
        if hdr_host:
            h2["host"] = [hdr_host]
        s["httpSettings"] = h2
    if sec == "tls":
        s["security"] = "tls"
        tls = {"serverName": _reality_server_name(parsed), "allowInsecure": False}
        if parsed.get("alpn"):
            tls["alpn"] = parsed["alpn"].split(",")
        if parsed.get("fp"):
            tls["fingerprint"] = parsed["fp"]
        s["tlsSettings"] = tls
    elif sec == "reality":
        s["security"] = "reality"
        r = {
            "serverName": _reality_server_name(parsed),
            "fingerprint": _vless_param(parsed, "fp", "fingerprint") or "chrome",
            "show": False,
            "publicKey": _vless_param(parsed, "pbk", "publicKey", "publickey"),
            "shortId": sanitize_short_id(_vless_param(parsed, "sid", "shortId")),
        }
        if parsed.get("spiderX"):
            r["spiderX"] = parsed["spiderX"]
        s["realitySettings"] = r
    else:
        s["security"] = "none"
    return s


def _build_outbound(parsed, tag):
    """Build a single VLESS outbound dict from parsed link."""
    ob = {
        "protocol": "vless",
        "tag": tag,
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
    flow = sanitize_flow(parsed.get("flow"))
    if flow:
        ob["settings"]["vnext"][0]["users"][0]["flow"] = flow
    return ob


def generate_full_config():
    """Generate config with all working world proxies + observatory + balancer."""
    rows = db_q(
        "SELECT link FROM proxies WHERE status='working' AND country != '' AND country != 'RU'"
    )
    proxy_obs = []
    for i, r in enumerate(rows):
        parsed = parse_vless(r["link"])
        if parsed:
            proxy_obs.append(_build_outbound(parsed, f"node{i}"))
    outbounds = proxy_obs + [
        {"protocol": "freedom", "tag": "direct"},
        {"protocol": "freedom", "tag": "api"},
    ]
    routing_rules = [
        {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
        {"inboundTag": ["api"], "outboundTag": "api"},
        {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
        {"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"},
    ]
    if proxy_obs:
        routing_rules.append(
            {"type": "field", "network": "tcp,udp", "balancerTag": "auto"}
        )
    config = {
        "api": {
            "tag": "api",
            "services": ["HandlerService", "RoutingService", "StatsService"],
        },
        "log": {"loglevel": "warning"},
        "inbounds": _proxy_inbounds(proxy_listen())
        + [
            {
                "listen": "127.0.0.1",
                "port": 10085,
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"},
                "tag": "api",
            }
        ],
        "outbounds": outbounds,
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": routing_rules},
    }
    if proxy_obs:
        config["observatory"] = {
            "subjectSelector": ["node"],
            "probeUrl": "https://www.gstatic.com/generate_204",
            "probeInterval": "30s",
            "enableConcurrency": True,
        }
        config["routing"]["balancers"] = [
            {
                "tag": "auto",
                "selector": ["node"],
                "strategy": {"type": "leastPing"},
            }
        ]
    return _inject_api(config)


def generate_base_config():
    """Minimal config for disk — proxies managed via API only."""
    base = {
        "api": {
            "tag": "api",
            "services": ["HandlerService", "RoutingService", "StatsService"],
        },
        "log": {"loglevel": "warning"},
        "inbounds": _proxy_inbounds(proxy_listen())
        + [
            {
                "listen": "127.0.0.1",
                "port": 10085,
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"},
                "tag": "api",
            }
        ],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "freedom", "tag": "api"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
                {"inboundTag": ["api"], "outboundTag": "api"},
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                {"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"},
                {"type": "field", "network": "tcp,udp", "balancerTag": "auto"},
            ],
            "balancers": [
                {
                    "tag": "auto",
                    "selector": ["node"],
                    "strategy": {"type": "leastPing"},
                }
            ],
        },
        "observatory": {
            "subjectSelector": ["node"],
            "probeUrl": "https://www.gstatic.com/generate_204",
            "probeInterval": "30s",
            "enableConcurrency": True,
        },
    }
    return _inject_api(base)


def apply_all_proxies():
    """Write minimal config to disk; manage proxies via Xray API only."""
    base = generate_base_config()
    cfg_path = xray_config_path()
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(base, indent=2))
    add_log("INFO", "Base config written to disk")

    config = generate_full_config()
    proxy_obs = [o for o in config["outbounds"] if o["tag"].startswith("node")]
    proxy_count = len(proxy_obs)

    if xray_api_ok():
        for tag in list_active_outbounds():
            if tag.startswith("node"):
                try:
                    subprocess.run(
                        [
                            xray_bin(),
                            "api",
                            "removeoutbound",
                            "-s",
                            "127.0.0.1:10085",
                            "--tag",
                            tag,
                        ],
                        capture_output=True,
                        timeout=10,
                    )
                except Exception:
                    pass
        for ob in proxy_obs:
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
            with tmp:
                json.dump({"outbound": ob}, tmp)
                tmp_path = tmp.name
            try:
                subprocess.run(
                    [
                        xray_bin(),
                        "api",
                        "addoutbound",
                        "-s",
                        "127.0.0.1:10085",
                        tmp_path,
                    ],
                    capture_output=True,
                    timeout=10,
                )
            except Exception:
                pass
            finally:
                os.unlink(tmp_path)
        add_log("INFO", f"Applied {proxy_count} proxies via API")


def list_active_outbounds():
    """Query xray API for current outbound tags."""
    try:
        r = subprocess.run(
            [xray_bin(), "api", "statsquery", "-s", "127.0.0.1:10085"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode != 0:
            return []
        tags = set()
        for line in r.stdout.splitlines():
            m = re.search(r"outbound>>>([^>]+)>>>traffic>>>([a-z]+)", line)
            if m:
                tags.add(m.group(1))
        return sorted(tags)
    except Exception:
        return []


def reimport_all_sources():
    rows = db_q("SELECT id, url FROM sources")
    total = 0
    for r in rows:
        added = import_from_url(r["url"])
        db_q("UPDATE sources SET last_import=? WHERE id=?", (datetime.now(), r["id"]))
        total += added
    if total:
        add_log("INFO", f"Hourly re-import: {total} new proxies")


def _check_one(row):
    ok, lat = test_proxy(row["link"])
    update_proxy_status(row["id"], ok, lat)
    return row["id"], row["host"], row["country"], ok


def background_checker():
    cycle = 0
    while True:
        time.sleep(60)
        cycle += 1

        rows = db_q("SELECT id, link, host, country FROM proxies")
        if not rows:
            if cycle % 60 == 0:
                reimport_all_sources()
            continue

        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = {pool.submit(_check_one, dict(r)): r for r in rows}
            for fut in as_completed(futures):
                try:
                    pid, host, country, ok = fut.result()
                except Exception:
                    pass
        enrich_all_unknown_countries()
        apply_all_proxies()

        if cycle % 60 == 0:
            reimport_all_sources()


# ─────────────────────── Helpers ───────────────────────


def proxy_filter_clause(f):
    if f == "working":
        return "WHERE status='working'"
    elif f == "failed_recent":
        return "WHERE status='failed' AND (failed_since IS NULL OR failed_since >= datetime('now', '-24 hours'))"
    elif f == "failed_old":
        return "WHERE status='failed' AND failed_since < datetime('now', '-24 hours')"
    return ""


# ─────────────────────── Routes — Pages ───────────────────────


@app.route("/")
def index():
    stats = db_q("SELECT status, COUNT(*) cnt FROM proxies GROUP BY status")
    s = {r["status"]: r["cnt"] for r in stats}
    return render_template(
        "index.html", total=sum(s.values()), working=s.get("working", 0)
    )


@app.route("/logs")
def logs():
    rows = db_q("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100")
    return render_template("logs.html", logs=rows)


@app.route("/sources")
def sources_page():
    return render_template("sources.html")


@app.route("/settings")
def settings_page():
    return render_template("settings.html")


# ─────────────────────── Routes — API Proxies ───────────────────────


@app.route("/api/proxies")
def api_proxies():
    f = request.args.get("filter", "")
    c = request.args.get("country", "")
    clause = proxy_filter_clause(f)
    if c == "RU":
        clause = (
            clause + " AND " if clause else "WHERE "
        ) + "status='working' AND country='RU'"
    elif c == "world":
        clause = (
            clause + " AND " if clause else "WHERE "
        ) + "status='working' AND country != '' AND country != 'RU'"
    rows = db_q(
        f"SELECT id, host, port, country, status, latency, failed_since, security, link FROM proxies {clause} ORDER BY status, latency"
    )
    return jsonify([dict(r) for r in rows])


@app.route("/api/status")
def api_status():
    total = db_q("SELECT COUNT(*) c FROM proxies")[0]["c"]
    working = db_q("SELECT COUNT(*) c FROM proxies WHERE status='working'")[0]["c"]
    failed_recent = db_q(
        "SELECT COUNT(*) c FROM proxies WHERE status='failed' AND (failed_since IS NULL OR failed_since >= datetime('now', '-24 hours'))"
    )[0]["c"]
    failed_old = db_q(
        "SELECT COUNT(*) c FROM proxies WHERE status='failed' AND failed_since < datetime('now', '-24 hours')"
    )[0]["c"]
    ru = db_q("SELECT COUNT(*) c FROM proxies WHERE status='working' AND country='RU'")[
        0
    ]["c"]
    world = db_q(
        "SELECT COUNT(*) c FROM proxies WHERE status='working' AND country != '' AND country != 'RU'"
    )[0]["c"]
    return jsonify(
        total=total,
        working=working,
        failed_recent=failed_recent,
        failed_old=failed_old,
        ru=ru,
        world=world,
    )


@app.route("/api/add", methods=["POST"])
def api_add():
    link = request.json.get("link", "").strip()
    parsed = parse_vless(link)
    if not parsed:
        return jsonify(error="Invalid VLESS link"), 400
    try:
        sec = parsed.get("security", "none") or "none"
        db_q(
            "INSERT INTO proxies (link,host,port,country,status,security,added_at) VALUES (?,?,?,?,?,?,?)",
            (
                link,
                parsed["host"],
                parsed["port"],
                parsed.get("country", ""),
                "pending",
                sec,
                datetime.now(),
            ),
        )
        add_log("INFO", f"Added proxy: {parsed['host']}:{parsed['port']}")
        threading.Thread(target=lambda: test_and_update(link), daemon=True).start()
        return jsonify(success=True)
    except sqlite3.IntegrityError:
        return jsonify(error="Already exists"), 409


def test_and_update(link):
    row = db_q("SELECT id FROM proxies WHERE link=?", (link,))
    if not row:
        return
    ok, lat = test_proxy(link)
    update_proxy_status(row[0]["id"], ok, lat)
    add_log("INFO", f"Tested {link[:50]} → {'working' if ok else 'failed'} ({lat}ms)")
    if ok:
        apply_all_proxies()


@app.route("/api/test/<int:pid>", methods=["POST"])
def api_test(pid):
    rows = db_q("SELECT link FROM proxies WHERE id=?", (pid,))
    if not rows:
        return jsonify(error="Not found"), 404
    ok, lat = test_proxy(rows[0]["link"])
    update_proxy_status(pid, ok, lat)
    status = "working" if ok else "failed"
    add_log("INFO", f"Tested proxy #{pid} → {status} ({lat}ms)")
    if ok:
        apply_all_proxies()
    return jsonify(status=status, latency=lat)


@app.route("/api/delete/<int:pid>", methods=["DELETE"])
def api_delete(pid):
    db_q("DELETE FROM proxies WHERE id=?", (pid,))
    add_log("INFO", f"Deleted proxy #{pid}")
    return jsonify(success=True)


@app.route("/api/test-all", methods=["POST"])
def api_test_all():
    threading.Thread(target=update_all, daemon=True).start()
    return jsonify(success=True)


def update_all():
    rows = db_q("SELECT id, link, host, country FROM proxies")
    if not rows:
        return
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(_check_one, dict(r)): r for r in rows}
        for fut in as_completed(futures):
            try:
                pid, host, country, ok = fut.result()
                if not country:
                    enrich_country(pid, host)
            except Exception:
                pass
    apply_all_proxies()


# ─────────────────────── Routes — API Sources ───────────────────────


@app.route("/api/sources", methods=["GET"])
def api_sources_list():
    rows = db_q("SELECT * FROM sources ORDER BY created_at DESC")
    return jsonify([dict(r) for r in rows])


@app.route("/api/sources", methods=["POST"])
def api_sources_add():
    name = request.json.get("name", "").strip()
    url = request.json.get("url", "").strip()
    if not name or not url:
        return jsonify(error="Name and URL required"), 400
    try:
        db_q(
            "INSERT INTO sources (name, url, created_at) VALUES (?, ?, ?)",
            (name, url, datetime.now()),
        )
        add_log("INFO", f"Added source: {name}")
        return jsonify(success=True)
    except sqlite3.IntegrityError:
        return jsonify(error="URL already exists"), 409


@app.route("/api/sources/<int:sid>", methods=["DELETE"])
def api_sources_delete(sid):
    db_q("DELETE FROM sources WHERE id=?", (sid,))
    add_log("INFO", f"Deleted source #{sid}")
    return jsonify(success=True)


@app.route("/api/sources/<int:sid>/import", methods=["POST"])
def api_sources_import_one(sid):
    rows = db_q("SELECT url FROM sources WHERE id=?", (sid,))
    if not rows:
        return jsonify(error="Not found"), 404
    added = import_from_url(rows[0]["url"])
    db_q("UPDATE sources SET last_import=? WHERE id=?", (datetime.now(), sid))
    threading.Thread(target=update_all, daemon=True).start()
    return jsonify(success=True, added=added)


@app.route("/api/sources/import-all", methods=["POST"])
def api_sources_import_all():
    rows = db_q("SELECT id, url FROM sources")
    total = 0
    for r in rows:
        added = import_from_url(r["url"])
        db_q("UPDATE sources SET last_import=? WHERE id=?", (datetime.now(), r["id"]))
        total += added
    threading.Thread(target=update_all, daemon=True).start()
    add_log("INFO", f"Imported {total} proxies from all sources")
    return jsonify(success=True, added=total)


# ─────────────────────── Routes — API Settings ───────────────────────


@app.route("/api/settings", methods=["GET"])
def api_settings_get():
    rows = db_q("SELECT key, value FROM settings ORDER BY key")
    return jsonify({r["key"]: r["value"] for r in rows})


@app.route("/api/settings", methods=["POST"])
def api_settings_set():
    data = request.json or {}
    for k, v in data.items():
        set_setting(k, str(v))
    add_log("INFO", f"Settings updated: {', '.join(data.keys())}")
    d = xray_diagnose()
    hint = None
    if d["systemd_active"]:
        if d["config_mismatch"]:
            hint = f"Panel config ≠ systemd. Set path to: {d['systemd_config_path']}"
        else:
            hint = "sudo systemctl restart xray"
    return jsonify(success=True, diagnose=d, restart_hint=hint)


@app.route("/api/xray-restart", methods=["POST"])
def api_xray_restart():
    ok = _systemctl_restart_xray()
    if ok:
        return jsonify(success=True, message="xray restarted via systemd")
    return jsonify(error="systemctl restart xray failed"), 500


@app.route("/api/xray/status", methods=["GET"])
def api_xray_status():
    api_ok = xray_api_ok()
    d = xray_diagnose()
    running = api_ok or (d["systemd_active"] and d["ports"].get("1080"))
    active = list_active_outbounds() if api_ok else []
    return jsonify(
        running=bool(running),
        api_accessible=api_ok,
        api_endpoint="127.0.0.1:10085",
        systemd_active=d["systemd_active"],
        config_mismatch=d["config_mismatch"],
        active_outbounds=active,
    )


@app.route("/api/xray/outbounds", methods=["GET"])
def api_xray_outbounds():
    tags = list_active_outbounds()
    nodes = [t for t in tags if t.startswith("node")]
    traffic = {}
    try:
        r = subprocess.run(
            [xray_bin(), "api", "statsquery", "-s", "127.0.0.1:10085"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in r.stdout.splitlines():
            m = re.search(r"outbound>>>([^>]+)>>>traffic>>>([a-z]+)", line)
            if m:
                tag, direction = m.group(1), m.group(2)
                traffic.setdefault(tag, {})[direction] = True
    except Exception:
        pass
    return jsonify(tags=tags, nodes=nodes, traffic=traffic)


@app.route("/api/xray/start", methods=["POST"])
def api_xray_start():
    try:
        r = subprocess.run(
            ["systemctl", "start", "xray"], capture_output=True, timeout=15
        )
        ok = r.returncode == 0
        msg = "started via systemd" if ok else r.stderr.decode()[:200]
    except Exception as e:
        ok, msg = False, str(e)
    if ok:
        add_log("INFO", "Xray started via systemd")
    else:
        add_log("ERROR", f"Xray start failed: {msg}")
    return jsonify(success=ok, message=msg)


@app.route("/api/xray/stop", methods=["POST"])
def api_xray_stop():
    try:
        subprocess.run(["systemctl", "stop", "xray"], capture_output=True, timeout=15)
    except Exception:
        pass
    add_log("INFO", "Xray stopped via systemd")
    return jsonify(success=True)


# ─────────────────────── Import ───────────────────────


@app.route("/api/import", methods=["POST"])
def api_import():
    url = request.json.get("url", "")
    added = import_from_url(url)
    threading.Thread(target=update_all, daemon=True).start()
    return jsonify(success=True, added=added)


def import_from_url(url):
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            content = r.read().decode("utf-8", errors="replace")
    except Exception as e:
        add_log("ERROR", f"Import failed for {url[:80]}: {e}")
        return 0
    links = [line for line in content.splitlines() if line.startswith("vless://")]
    added = 0
    for link in links:
        parsed = parse_vless(link)
        if not parsed:
            continue
        try:
            sec = parsed.get("security", "none") or "none"
            db_q(
                "INSERT OR IGNORE INTO proxies (link,host,port,country,status,security,added_at) VALUES (?,?,?,?,?,?,?)",
                (
                    link,
                    parsed["host"],
                    parsed["port"],
                    parsed.get("country", ""),
                    "pending",
                    sec,
                    datetime.now(),
                ),
            )
            added += 1
        except sqlite3.IntegrityError:
            pass
    if added:
        add_log("INFO", f"Imported {added} proxies from {url[:60]}")
    return added


# ─────────────────────── Main ───────────────────────


def _systemctl_restart_xray():
    """Restart systemd xray via systemctl. Uses sudo only if not root."""
    cmd = ["systemctl", "restart", "xray"]
    if os.geteuid() != 0:
        cmd.insert(0, "sudo")
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=15)
        if r.returncode == 0:
            add_log("INFO", "systemd xray restarted")
            return True
        add_log("WARN", f"systemctl restart xray failed: {r.stderr.decode()[:200]}")
    except Exception as e:
        add_log("WARN", f"Could not restart systemd xray: {e}")
    return False


if __name__ == "__main__":
    init_db()
    # log current settings
    rows = db_q("SELECT key, value FROM settings ORDER BY key")
    print("  Settings loaded:")
    for r in rows:
        print(f"    {r['key']}: {r['value'][:60]}")

    # Write fresh config and hot-apply via API
    apply_all_proxies()

    # Clean up long country names from old imports
    enrich_all_unknown_countries()

    threading.Thread(target=background_checker, daemon=True).start()
    print("  +- VLESS Manager -----------------------------+")
    print("  |  http://127.0.0.1:5000                      |")
    print("  +---------------------------------------------+")
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
