"""Генерация конфига Xray, горячее применение через API и кеширование подписки."""

import json
import threading

from .db import db_q, get_setting, xray_config_path, proxy_listen
from .utils import add_log, moscow_str, SUBSCRIBE_FILE
from .vless import parse_vless, stream_settings, sanitize_flow, _sanitize_outbounds
from .xray_api import xray_api_ok, remove_all_outbounds, add_outbound
from config import (SOCKS_PORT, HTTP_PORT, API_PORT, API_LISTEN,
                     PROBE_INTERVAL)

_apply_lock = threading.Lock()


# ─── Inbounds / Base config ───


def _proxy_inbounds(listen):
    """Возвращает SOCKS и HTTP inbound для заданного адреса прослушивания."""
    return [
        {
            "port": SOCKS_PORT,
            "listen": listen,
            "protocol": "socks",
            "settings": {"udp": True},
        },
        {"port": HTTP_PORT, "listen": listen, "protocol": "http", "settings": {}},
    ]


def _apply_proxy_listen(cfg):
    """Устанавливает listen-адрес на SOCKS/HTTP inbounds; API inbound всегда 127.0.0.1."""
    listen = proxy_listen()
    for ib in cfg.get("inbounds", []):
        if ib.get("protocol") in ("socks", "http"):
            ib["listen"] = listen
    return cfg


def _inject_api(cfg):
    """Добавляет в конфиг API-секцию, inbound, outbound и routing rule."""
    _apply_proxy_listen(cfg)
    cfg.setdefault(
        "api", {"tag": "api", "services": ["HandlerService", "RoutingService"]}
    )
    api_inbound = {
        "listen": API_LISTEN,
        "port": API_PORT,
        "protocol": "dokodemo-door",
        "settings": {"address": API_LISTEN},
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


# ─── Генерация конфига ───


def _build_outbound(parsed, tag):
    """Строит один VLESS outbound из распарсенной ссылки."""
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


def generate_full_config(max_outbounds=0):
    """Генерирует полный конфиг с observatory + balancer.

    Если max_outbounds > 0 — только N самых быстрых outbound.
    Учитывает фильтр allowed_countries.
    """
    allowed = get_setting("allowed_countries", "").strip()
    if allowed:
        codes = [c.strip() for c in allowed.split(",") if c.strip()]
        if codes:
            placeholders = ",".join("?" * len(codes))
            country_sql = f"AND country IN ({placeholders})"
            limit_sql = " ORDER BY latency" if max_outbounds > 0 else ""
            rows = db_q(
                f"SELECT link FROM proxies WHERE status='working' {country_sql}{limit_sql}",
                codes,
            )
        else:
            rows = []
    else:
        limit_sql = " ORDER BY latency" if max_outbounds > 0 else ""
        rows = db_q(
            f"SELECT link FROM proxies WHERE status='working' AND country != '' AND country != 'RU'{limit_sql}"
        )
    proxy_obs = []
    for i, r in enumerate(rows):
        if max_outbounds > 0 and i >= max_outbounds:
            break
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
                "listen": API_LISTEN,
                "port": API_PORT,
                "protocol": "dokodemo-door",
                "settings": {"address": API_LISTEN},
                "tag": "api",
            }
        ],
        "outbounds": outbounds,
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": routing_rules},
    }
    if proxy_obs:
        config["observatory"] = {
            "subjectSelector": ["node"],
            "probeUrl": get_setting("probe_url"),
            "probeInterval": PROBE_INTERVAL,
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
    """Минимальный конфиг для диска — прокси управляются только через API."""
    base = {
        "api": {
            "tag": "api",
            "services": ["HandlerService", "RoutingService", "StatsService"],
        },
        "log": {"loglevel": "warning"},
        "inbounds": _proxy_inbounds(proxy_listen())
        + [
            {
                "listen": API_LISTEN,
                "port": API_PORT,
                "protocol": "dokodemo-door",
                "settings": {"address": API_LISTEN},
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
            "probeUrl": get_setting("probe_url"),
            "probeInterval": PROBE_INTERVAL,
            "enableConcurrency": True,
        },
    }
    return _inject_api(base)


# ─── Применение конфига ───


def apply_all_proxies():
    """Пишет минимальный конфиг на диск, прокси добавляет через Xray API.

    Блокировка _apply_lock предотвращает конкурентные вызовы.
    """
    if not _apply_lock.acquire(blocking=False):
        add_log("WARN", "Config rebuild already in progress — skipping")
        return
    try:
        _apply_all_proxies_impl()
    finally:
        _apply_lock.release()


def _apply_all_proxies_impl():
    """Внутренняя реализация применения конфига (без блокировки)."""
    cfg_path = xray_config_path()
    cfg_path.parent.mkdir(parents=True, exist_ok=True)

    config = generate_full_config()
    proxy_obs = [o for o in config["outbounds"] if o["tag"].startswith("node")]
    proxy_count = len(proxy_obs)
    max_active = int(get_setting("max_active_proxies", "100"))

    if xray_api_ok():
        base = generate_base_config()
        cfg_path.write_text(json.dumps(base, indent=2))
        add_log("INFO", "Base config written to disk")

        limited = generate_full_config(max_outbounds=max_active)
        limited_obs = [o for o in limited["outbounds"] if o["tag"].startswith("node")]

        remove_all_outbounds()
        for ob in limited_obs:
            add_outbound(ob)
        add_log(
            "INFO",
            f"Applied {len(limited_obs)} proxies via API (total working: {proxy_count})",
        )
    else:
        limited = generate_full_config(max_outbounds=max_active)
        cfg_path.write_text(json.dumps(limited, indent=2))
        applied = sum(1 for o in limited["outbounds"] if o["tag"].startswith("node"))
        add_log(
            "WARN",
            f"Xray API unavailable — wrote {applied} proxies to disk (total working: {proxy_count})",
        )
    _update_subscribe_cache()


# ─── Кеш подписки ───


def _update_subscribe_cache():
    """Собирает subscribe.txt с vless-ссылками + метаданными для внешних клиентов.

    Формат: #profile-title, # Updated, # Configs, затем vless:// ссылки.
    """
    max_active = int(get_setting("max_active_proxies", "30"))
    allowed = get_setting("allowed_countries", "").strip()
    rows = db_q(
        "SELECT link FROM proxies WHERE status='working' AND country != '' AND country != 'RU' ORDER BY latency LIMIT ?",
        (max_active,),
    )
    total_all = db_q("SELECT COUNT(*) c FROM proxies")[0]["c"]
    total_working = db_q("SELECT COUNT(*) c FROM proxies WHERE status='working'")[0]["c"]
    probe_url = get_setting("probe_url")
    now = moscow_str()
    lines = [
        "#profile-title: VLESS Manager",
        "#profile-update-interval: 1",
        f"# Updated: {now}",
        f"# Configs: {len(rows)} / {total_working} working / {total_all} total",
    ]
    if allowed:
        lines.append(f"# Filter: {allowed}")
    lines.append(f"# Probe: {probe_url}")
    lines.append("")
    for r in rows:
        lines.append(r["link"])
    SUBSCRIBE_FILE.write_text("\n".join(lines), encoding="utf-8")
