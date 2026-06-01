"""Генерация конфига Xray, горячее применение через API, диагностика, подписка."""

import json
import os
import re
import subprocess
import tempfile
import threading
from pathlib import Path

from .db import db_q, Settings, xray_config_path
from .utils import add_log, moscow_str
from config import SUBSCRIBE_FILE
from .vless import parse_vless, stream_settings, sanitize_flow
from config import SOCKS_PORT, HTTP_PORT, API_PORT, API_LISTEN, PROBE_INTERVAL


class XrayConfigurator:
    """Управление конфигурацией Xray: генерация, применение через API, диагностика."""

    def __init__(self):
        """Инициализирует блокировку для предотвращения конкурентных применений конфига."""
        self._apply_lock = threading.Lock()

    # ─── Inbounds / Base config helpers ───

    @staticmethod
    def _proxy_inbounds(listen):
        """Возвращает SOCKS и HTTP inbound для заданного адреса прослушивания."""
        return [
            {"port": SOCKS_PORT, "listen": listen, "protocol": "socks", "settings": {"udp": True}},
            {"port": HTTP_PORT, "listen": listen, "protocol": "http", "settings": {}},
        ]

    @staticmethod
    def _apply_proxy_listen(cfg):
        """Устанавливает listen-адрес на SOCKS/HTTP inbounds."""
        listen = Settings.proxy_listen()
        for ib in cfg.get("inbounds", []):
            if ib.get("protocol") in ("socks", "http"):
                ib["listen"] = listen
        return cfg

    def _inject_api(self, cfg):
        """Добавляет в конфиг API-секцию, inbound, outbound и routing rule."""
        self._apply_proxy_listen(cfg)
        cfg.setdefault("api", {"tag": "api", "services": ["HandlerService", "RoutingService"]})
        api_inbound = {
            "listen": API_LISTEN, "port": API_PORT, "protocol": "dokodemo-door",
            "settings": {"address": API_LISTEN}, "tag": "api",
        }
        if not any(ib.get("tag") == "api" for ib in cfg.get("inbounds", [])):
            cfg.setdefault("inbounds", []).append(api_inbound)
        api_out = {"protocol": "freedom", "tag": "api"}
        if not any(o.get("tag") == "api" for o in cfg.get("outbounds", [])):
            cfg.setdefault("outbounds", []).append(api_out)
        api_rule = {"inboundTag": ["api"], "outboundTag": "api"}
        rules = cfg.setdefault("routing", {}).setdefault("rules", [])
        if not any(r.get("outboundTag") == "api" for r in rules):
            rules.append(api_rule)
        from .vless import _sanitize_outbounds
        _sanitize_outbounds(cfg)
        return cfg

    @staticmethod
    def _build_outbound(parsed, tag):
        """Строит один VLESS outbound из распарсенной ссылки."""
        ob = {
            "protocol": "vless", "tag": tag,
            "settings": {"vnext": [{
                "address": parsed["server"], "port": parsed["port"],
                "users": [{"id": parsed["uid"], "encryption": "none"}],
            }]},
            "streamSettings": stream_settings(parsed),
        }
        flow = sanitize_flow(parsed.get("flow"))
        if flow:
            ob["settings"]["vnext"][0]["users"][0]["flow"] = flow
        return ob

    # ─── Config generation ───

    def generate_full_config(self, max_outbounds=0):
        """Генерирует полный конфиг с observatory + balancer.

        Если max_outbounds > 0 — только N самых быстрых outbound.
        Учитывает фильтр allowed_countries.
        """
        allowed = Settings.allowed_countries()
        codes = [c.strip() for c in allowed.split(",") if c.strip()] if allowed else []
        if codes:
            placeholders = ",".join("?" * len(codes))
            country_sql = f"AND country IN ({placeholders})"
        else:
            codes = []
            country_sql = ""
        limit_sql = " ORDER BY latency_vless" if max_outbounds > 0 else ""
        rows = db_q(
            f"SELECT link FROM proxies WHERE status='working' AND latency_vless > 0 {country_sql}{limit_sql}",
            codes,
        )
        proxy_obs = []
        for i, r in enumerate(rows):
            if max_outbounds > 0 and i >= max_outbounds:
                break
            parsed = parse_vless(r["link"])
            if parsed:
                proxy_obs.append(self._build_outbound(parsed, f"node{i}"))
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
            routing_rules.append({"type": "field", "network": "tcp,udp", "balancerTag": "auto"})
        config = {
            "api": {"tag": "api", "services": ["HandlerService", "RoutingService", "StatsService"]},
            "log": {"loglevel": "warning"},
            "inbounds": self._proxy_inbounds(Settings.proxy_listen())
                        + [{"listen": API_LISTEN, "port": API_PORT, "protocol": "dokodemo-door",
                            "settings": {"address": API_LISTEN}, "tag": "api"}],
            "outbounds": outbounds,
            "routing": {"domainStrategy": "IPIfNonMatch", "rules": routing_rules},
        }
        if proxy_obs:
            config["observatory"] = {
                "subjectSelector": ["node"],
                "probeUrl": Settings.probe_url(),
                "probeInterval": PROBE_INTERVAL,
                "enableConcurrency": True,
            }
            config["routing"]["balancers"] = [{"tag": "auto", "selector": ["node"], "strategy": {"type": "leastPing"}}]
        return self._inject_api(config)

    def generate_base_config(self):
        """Минимальный конфиг для диска — прокси управляются только через API."""
        base = {
            "api": {"tag": "api", "services": ["HandlerService", "RoutingService", "StatsService"]},
            "log": {"loglevel": "warning"},
            "inbounds": self._proxy_inbounds(Settings.proxy_listen())
                        + [{"listen": API_LISTEN, "port": API_PORT, "protocol": "dokodemo-door",
                            "settings": {"address": API_LISTEN}, "tag": "api"}],
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
                "balancers": [{"tag": "auto", "selector": ["node"], "strategy": {"type": "leastPing"}}],
            },
            "observatory": {
                "subjectSelector": ["node"],
                "probeUrl": Settings.probe_url(),
                "probeInterval": PROBE_INTERVAL,
                "enableConcurrency": True,
            },
        }
        return self._inject_api(base)

    # ─── Xray API helpers ───

    @staticmethod
    def api_ok():
        """Проверяет, отвечает ли Xray API."""
        try:
            r = subprocess.run(
                [Settings.xray_bin(), "api", "statsquery", "-s", f"{API_LISTEN}:{API_PORT}"],
                capture_output=True, timeout=5,
            )
            return r.returncode == 0
        except Exception as e:
            add_log("DEBUG", f"Xray API check failed: {e}")
            return False

    @staticmethod
    def list_active_outbounds():
        """Возвращает список тегов активных outbound через Xray API statsquery."""
        try:
            r = subprocess.run(
                [Settings.xray_bin(), "api", "statsquery", "-s", f"{API_LISTEN}:{API_PORT}"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode != 0:
                return []
            tags = set()
            for line in r.stdout.splitlines():
                m = re.search(r"outbound>>>([^>]+)>>>traffic>>>([a-z]+)", line)
                if m:
                    tags.add(m.group(1))
            return sorted(tags)
        except Exception as e:
            add_log("DEBUG", f"Failed to list active outbounds: {e}")
            return []

    @staticmethod
    def remove_all_outbounds():
        """Удаляет все node* outbound из Xray через API."""
        for tag in XrayConfigurator.list_active_outbounds():
            if tag.startswith("node"):
                try:
                    subprocess.run(
                        [Settings.xray_bin(), "api", "removeoutbound", "-s", f"{API_LISTEN}:{API_PORT}", "--tag", tag],
                        capture_output=True, timeout=10,
                    )
                except Exception as e:
                    add_log("DEBUG", f"Failed to remove outbound {tag}: {e}")

    @staticmethod
    def add_outbound(ob):
        """Добавляет один outbound в Xray через API (через временный JSON-файл)."""
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        with tmp:
            json.dump({"outbound": ob}, tmp)
            tmp_path = tmp.name
        try:
            subprocess.run(
                [Settings.xray_bin(), "api", "addoutbound", "-s", f"{API_LISTEN}:{API_PORT}", tmp_path],
                capture_output=True, timeout=10,
            )
        except Exception as e:
            add_log("DEBUG", f"Failed to add outbound: {e}")
        finally:
            os.unlink(tmp_path)

    @staticmethod
    def restart_via_systemd():
        """Перезапускает systemd-сервис xray. Использует sudo, если не root."""
        cmd = ["systemctl", "restart", "xray"]
        try:
            if os.geteuid() != 0:
                cmd.insert(0, "sudo")
        except AttributeError:
            pass
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=15)
            if r.returncode == 0:
                add_log("INFO", "systemd xray restarted")
                return True
            add_log("WARN", f"systemctl restart xray failed: {r.stderr.decode()[:200]}")
        except Exception as e:
            add_log("WARN", f"Could not restart systemd xray: {e}")
        return False

    # ─── Apply config ───

    def apply_all(self):
        """Пишет минимальный конфиг на диск, прокси добавляет через Xray API.

        Блокировка _apply_lock предотвращает конкурентные вызовы.
        """
        if not self._apply_lock.acquire(blocking=False):
            add_log("WARN", "Config rebuild already in progress — skipping")
            return
        try:
            self._apply_all_impl()
        finally:
            self._apply_lock.release()

    def _apply_all_impl(self):
        """Внутренняя реализация применения конфига (без блокировки)."""
        cfg_path = xray_config_path()
        cfg_path.parent.mkdir(parents=True, exist_ok=True)

        config = self.generate_full_config()
        proxy_obs = [o for o in config["outbounds"] if o["tag"].startswith("node")]
        proxy_count = len(proxy_obs)
        max_active = Settings.max_active_proxies()

        if self.api_ok():
            base = self.generate_base_config()
            cfg_path.write_text(json.dumps(base, indent=2))
            add_log("INFO", "Base config written to disk")

            limited = self.generate_full_config(max_outbounds=max_active)
            limited_obs = [o for o in limited["outbounds"] if o["tag"].startswith("node")]

            self.remove_all_outbounds()
            for ob in limited_obs:
                self.add_outbound(ob)
            add_log("INFO", f"Applied {len(limited_obs)} proxies via API (total working: {proxy_count})")
        else:
            limited = self.generate_full_config(max_outbounds=max_active)
            cfg_path.write_text(json.dumps(limited, indent=2))
            applied = sum(1 for o in limited["outbounds"] if o["tag"].startswith("node"))
            add_log("WARN", f"Xray API unavailable — wrote {applied} proxies to disk (total working: {proxy_count})")
        self._update_subscribe_cache()

    # ─── Subscribe cache ───

    def _update_subscribe_cache(self):
        """Собирает subscribe.txt с vless-ссылками + метаданными для внешних клиентов."""
        max_active = Settings.max_active_proxies()
        allowed = Settings.allowed_countries()
        codes = [c.strip() for c in allowed.split(",") if c.strip()] if allowed else []
        if codes:
            placeholders = ",".join("?" * len(codes))
            country_sql = f"AND country IN ({placeholders})"
        else:
            placeholders = ""
            country_sql = ""
            codes = []
        rows = db_q(
            f"SELECT link FROM proxies WHERE status='working' AND latency_vless > 0 {country_sql} ORDER BY latency LIMIT ?",
            codes + [max_active],
        )
        total_all = db_q("SELECT COUNT(*) c FROM proxies")[0]["c"]
        total_working = db_q("SELECT COUNT(*) c FROM proxies WHERE status='working'")[0]["c"]
        probe_url = Settings.probe_url()
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

    # ─── Diagnosis ───

    @staticmethod
    def _detect_systemd_config():
        """Извлекает путь к конфигу Xray из systemd unit (ExecStart)."""
        try:
            r = subprocess.run(
                ["systemctl", "show", "xray", "-p", "ExecStart", "--value"],
                capture_output=True, text=True, timeout=3,
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
        except Exception as e:
            add_log("WARN", f"Failed to detect systemd xray config path: {e}")
        return None

    @staticmethod
    def _systemd_active():
        """Проверяет, активен ли systemd-сервис xray."""
        try:
            r = subprocess.run(["systemctl", "is-active", "xray"], capture_output=True, text=True, timeout=3)
            return r.stdout.strip() == "active"
        except Exception as e:
            add_log("DEBUG", f"Failed to check systemd active: {e}")
            return False

    @staticmethod
    def _ss_listen(port):
        """Проверяет, слушает ли процесс указанный TCP-порт (через ss)."""
        try:
            r = subprocess.run(["ss", "-lntp"], capture_output=True, text=True, timeout=3)
            for line in (r.stdout or "").splitlines():
                if f":{port}" in line:
                    return line.strip()
        except Exception as e:
            add_log("DEBUG", f"Failed to check port {port}: {e}")
        return None

    def _config_inbound_listeners(self, path=None):
        """Читает входящие соединения (socks/http) из JSON-конфига."""
        p = Path(path) if path else xray_config_path()
        if not p.exists():
            return []
        try:
            data = json.loads(p.read_text())
            return [
                {"protocol": ib.get("protocol"), "port": ib.get("port"), "listen": ib.get("listen")}
                for ib in data.get("inbounds", [])
                if ib.get("protocol") in ("socks", "http")
            ]
        except Exception as e:
            add_log("DEBUG", f"Failed to read config inbounds: {e}")
            return []

    def diagnose(self):
        """Собирает диагностическую информацию о состоянии Xray."""
        mgr = str(xray_config_path().resolve())
        systemd_cfg = self._detect_systemd_config()
        inbounds = self._config_inbound_listeners()
        has_socks = any(
            ib.get("port") == 1080 and ib.get("protocol") == "socks" for ib in inbounds
        )
        return {
            "manager_config_path": mgr,
            "systemd_config_path": systemd_cfg,
            "config_mismatch": bool(systemd_cfg and systemd_cfg != mgr),
            "systemd_active": self._systemd_active(),
            "config_inbounds": inbounds,
            "socks_in_config": has_socks,
            "ports": {str(p): self._ss_listen(p) for p in (1080, 1081, 10085)},
            "proxy_listen": Settings.proxy_listen(),
        }


xray_configurator = XrayConfigurator()
