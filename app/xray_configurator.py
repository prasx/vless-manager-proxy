"""Генерация конфига Xray, горячее применение через API, диагностика, подписка."""

import hashlib
import json
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from .db import db_q, Settings, xray_config_path
from .utils import add_log, moscow_str
from config import SUBSCRIBE_FILE
from .vless import parse_vless, stream_settings, sanitize_flow
from config import SOCKS_PORT, HTTP_PORT, API_PORT, API_LISTEN


class XrayConfigurator:
    """Управление конфигурацией Xray: генерация, применение через API, диагностика."""

    def __init__(self):
        """Инициализирует блокировку для предотвращения конкурентных применений конфига."""
        self._apply_lock = threading.Lock()
        self._last_config_hash = ""

    # ─── Inbounds / Base config helpers ───

    @staticmethod
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

    _geosite_checked = False
    _geosite_available = False

    @classmethod
    def _reset_geosite_cache(cls):
        """Сбрасывает кеш geosite.dat — принудительная перепроверка."""
        cls._geosite_checked = False

    @classmethod
    def _geosite_available_check(cls):
        """Проверяет, доступен ли geosite.dat (с кешированием)."""
        if cls._geosite_checked:
            return cls._geosite_available
        cls._geosite_checked = True
        # Стандартные пути, где Xray ищет geosite.dat
        candidates = [
            "/usr/local/share/xray",
            "/usr/local/lib/xray",
            "/etc/xray",
            "/opt/xray",
        ]
        # XRAY_LOCATION_ASSET
        env_asset = os.environ.get("XRAY_LOCATION_ASSET", "")
        if env_asset:
            candidates.insert(0, env_asset)
        # Директория бинарника Xray
        xray_bin = Settings.xray_bin()
        if "/" in xray_bin:
            candidates.insert(0, os.path.dirname(xray_bin))
        for d in candidates:
            p = os.path.join(d, "geosite.dat")
            if os.path.isfile(p):
                cls._geosite_available = True
                return True
        cls._geosite_available = False
        add_log(
            "WARN",
            "geosite.dat not found — GeoSite rules disabled. Set XRAY_LOCATION_ASSET or verify Xray installation",
        )
        return False

    @classmethod
    def _geosite_rules(cls, has_balancer=True):
        """Возвращает список routing-правил из настроек geosite_rules.
        has_balancer=False — правило proxy → direct (нет рабочих прокси)."""
        if not cls._geosite_available_check():
            return []
        rules = []
        for item in Settings.geosite_rules():
            domain = (item.get("domain") or "").strip()
            tag = (item.get("outboundTag") or "").strip()
            if not domain:
                continue
            if tag == "proxy":
                if has_balancer:
                    rules.append(
                        {"type": "field", "domain": [domain], "balancerTag": "auto"}
                    )
                else:
                    rules.append(
                        {"type": "field", "domain": [domain], "outboundTag": "direct"}
                    )
            elif tag == "direct":
                rules.append(
                    {"type": "field", "domain": [domain], "outboundTag": "direct"}
                )
        return rules

    # ─── Config generation ───

    def generate_full_config(self, max_outbounds=0, skip_geosite=False):
        """Генерирует полный конфиг с observatory + balancer.

        Если max_outbounds > 0 — только N самых быстрых outbound.
        Учитывает фильтр allowed_countries.
        skip_geosite=True — временно исключить geosite-правила (для recovery).
        """
        allowed = Settings.allowed_countries()
        codes = [c.strip() for c in allowed.split(",") if c.strip()] if allowed else []
        if codes:
            placeholders = ",".join("?" * len(codes))
            country_sql = f"AND country IN ({placeholders})"
        else:
            codes = []
            country_sql = ""
        proxy_obs = []
        if max_outbounds > 0:
            rows = db_q(
                f"SELECT link FROM proxies WHERE status='working' AND latency_vless > 0 {country_sql} ORDER BY speed_kbps > 0 DESC, speed_kbps DESC, latency_vless ASC LIMIT ?",
                codes + [max_outbounds],
            )
            for r in rows:
                parsed = parse_vless(r["link"])
                if parsed:
                    proxy_obs.append(
                        self._build_outbound(parsed, f"node{len(proxy_obs)}")
                    )
        else:
            rows = db_q(
                f"SELECT link FROM proxies WHERE status='working' AND latency_vless > 0 {country_sql}",
                codes,
            )
            for r in rows:
                parsed = parse_vless(r["link"])
                if parsed:
                    proxy_obs.append(
                        self._build_outbound(parsed, f"node{len(proxy_obs)}")
                    )
        outbounds = proxy_obs + [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "freedom", "tag": "api"},
        ]
        routing_rules = [
            {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
            {"inboundTag": ["api"], "outboundTag": "api"},
        ]
        if Settings.get("geo_enabled", "true") == "true":
            routing_rules.extend(
                [
                    {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                    {"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"},
                ]
            )
            if not skip_geosite:
                routing_rules.extend(self._geosite_rules(has_balancer=bool(proxy_obs)))
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
            "inbounds": self._proxy_inbounds(Settings.proxy_listen())
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
                "probeUrl": Settings.probe_url(),
                "probeInterval": Settings.get("observatory_probe_interval", "10s"),
                "enableConcurrency": True,
            }
            config["routing"]["balancers"] = [
                {"tag": "auto", "selector": ["node"], "strategy": {"type": "leastPing"}}
            ]
        return self._inject_api(config)

    def generate_base_config(self):
        """Минимальный конфиг для диска — прокси управляются только через API."""
        has_geo = Settings.get("geo_enabled", "true") == "true"
        geo_rules = []
        if has_geo:
            geo_rules = [
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                {"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"},
            ] + self._geosite_rules()
        base = {
            "api": {
                "tag": "api",
                "services": ["HandlerService", "RoutingService", "StatsService"],
            },
            "log": {"loglevel": "warning"},
            "inbounds": self._proxy_inbounds(Settings.proxy_listen())
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
                    {
                        "type": "field",
                        "protocol": ["bittorrent"],
                        "outboundTag": "direct",
                    },
                    {"inboundTag": ["api"], "outboundTag": "api"},
                ]
                + geo_rules
                + [
                    {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
                ],
            },
        }
        return self._inject_api(base)

    # ─── Xray API helpers ───

    @staticmethod
    def api_ok():
        """Проверяет, отвечает ли Xray API (сначала TCP, потом gRPC)."""
        try:
            s = socket.create_connection((API_LISTEN, API_PORT), timeout=2)
            s.close()
        except Exception:
            return False
        try:
            r = subprocess.run(
                [
                    Settings.xray_bin(),
                    "api",
                    "statsquery",
                    "-s",
                    f"{API_LISTEN}:{API_PORT}",
                ],
                capture_output=True,
                timeout=5,
            )
            return r.returncode == 0
        except Exception:
            return False

    @staticmethod
    def list_active_outbounds():
        """Возвращает список тегов активных outbound через xray api statsquery."""
        try:
            r = subprocess.run(
                [
                    Settings.xray_bin(),
                    "api",
                    "statsquery",
                    "-s",
                    f"{API_LISTEN}:{API_PORT}",
                ],
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
        except Exception as e:
            add_log("DEBUG", f"Failed to list active outbounds: {e}")
            return []

    @staticmethod
    def remove_all_outbounds():
        """Удаляет все node* outbound из Xray через API. Логирует ошибки."""
        for tag in XrayConfigurator.list_active_outbounds():
            if tag.startswith("node"):
                try:
                    r = subprocess.run(
                        [
                            Settings.xray_bin(),
                            "api",
                            "removeoutbound",
                            "-s",
                            f"{API_LISTEN}:{API_PORT}",
                            "--tag",
                            tag,
                        ],
                        capture_output=True,
                        timeout=10,
                    )
                    if r.returncode != 0:
                        add_log(
                            "DEBUG",
                            f"Remove outbound {tag} failed (code {r.returncode}): {r.stderr.decode(errors='replace')[:200]}",
                        )
                except Exception as e:
                    add_log("DEBUG", f"Failed to remove outbound {tag}: {e}")

    @staticmethod
    def add_outbound(ob):
        """Добавляет один outbound в Xray через API. Логирует ошибки."""
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        with tmp:
            json.dump({"outbound": ob}, tmp)
            tmp_path = tmp.name
        ok = False
        try:
            r = subprocess.run(
                [
                    Settings.xray_bin(),
                    "api",
                    "addoutbound",
                    "-s",
                    f"{API_LISTEN}:{API_PORT}",
                    tmp_path,
                ],
                capture_output=True,
                timeout=10,
            )
            if r.returncode == 0:
                ok = True
            else:
                add_log(
                    "DEBUG",
                    f"Add outbound failed (code {r.returncode}): {r.stderr.decode(errors='replace')[:200]}",
                )
        except Exception as e:
            add_log("DEBUG", f"Failed to add outbound: {e}")
        finally:
            os.unlink(tmp_path)
        return ok

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

    # ─── Config hash (skip if unchanged) ───

    def _compute_config_hash(self):
        """Хэш входных данных для конфига — если не изменился, apply_all можно пропустить."""
        max_active = Settings.max_active_proxies()
        allowed = Settings.allowed_countries()
        codes = [c.strip() for c in allowed.split(",") if c.strip()] if allowed else []
        sort_col = "speed_kbps > 0 DESC, speed_kbps DESC, latency_vless ASC"
        if codes:
            placeholders = ",".join("?" * len(codes))
            rows = db_q(
                f"SELECT link FROM proxies WHERE status='working' AND latency_vless > 0 AND country IN ({placeholders}) ORDER BY {sort_col} LIMIT ?",
                codes + [max_active],
            )
        else:
            rows = db_q(
                f"SELECT link FROM proxies WHERE status='working' AND latency_vless > 0 ORDER BY {sort_col} LIMIT ?",
                (max_active,),
            )
        links = "|".join(r["link"] for r in rows)
        sig = "|".join(
            [
                links,
                str(max_active),
                allowed,
                Settings.proxy_listen(),
                Settings.get("geo_enabled", "true"),
                Settings.get("geosite_rules", "[]"),
                Settings.probe_url(),
                Settings.get("observatory_probe_interval", "10s"),
            ]
        )
        return hashlib.sha256(sig.encode()).hexdigest()

    # ─── Apply config ───

    def apply_all(self, blocking=False):
        """Пишет полный конфиг на диск, прокси добавляет через Xray API.

        blocking=True — ждать освобождения _apply_lock (для финального apply после тестов).
        blocking=False — пропустить, если другой apply уже выполняется.
        """
        if not self._apply_lock.acquire(blocking=blocking):
            add_log("WARN", "Config rebuild already in progress — skipping")
            return
        try:
            self._apply_all_impl()
        finally:
            self._apply_lock.release()

    def _apply_all_impl(self):
        """Внутренняя реализация применения конфига (без блокировки)."""
        try:
            self._apply_all_impl_safe()
        except Exception as e:
            add_log("ERROR", f"Config rebuild failed: {e}")

    def _active_node_count(self):
        """Сколько node* outbound сейчас в running Xray (0, если API недоступен)."""
        if not self.api_ok():
            return 0
        return sum(1 for t in self.list_active_outbounds() if t.startswith("node"))

    def _apply_all_impl_safe(self):
        cfg_path = xray_config_path()
        cfg_path.parent.mkdir(parents=True, exist_ok=True)

        max_active = Settings.max_active_proxies()
        proxy_count = db_q(
            "SELECT COUNT(*) c FROM proxies WHERE status='working' AND latency_vless > 0"
        )[0]["c"]
        expected_nodes = min(proxy_count, max_active) if max_active > 0 else proxy_count

        new_hash = self._compute_config_hash()
        if new_hash == self._last_config_hash:
            active_nodes = self._active_node_count()
            if active_nodes >= expected_nodes:
                return
            add_log(
                "WARN",
                f"Hash unchanged but only {active_nodes}/{expected_nodes} outbounds running — reapplying",
            )
        self._last_config_hash = new_hash

        has_work = proxy_count > 0

        geosite_rules_list = self._geosite_rules(has_balancer=has_work)
        if geosite_rules_list:
            domains = [r["domain"][0] for r in geosite_rules_list if "domain" in r]
            add_log(
                "INFO",
                f"GeoSite rules active ({len(geosite_rules_list)}): {', '.join(domains)}",
            )
        else:
            add_log("DEBUG", "No GeoSite rules configured — all domains via balancer")

        full = self.generate_full_config(max_outbounds=max_active)
        limited_obs = [o for o in full["outbounds"] if o["tag"].startswith("node")]

        if self.api_ok():
            cfg_path.write_text(json.dumps(full, indent=2))
            add_log("INFO", "Full config written to disk")

            self.remove_all_outbounds()
            added = 0
            for ob in limited_obs:
                if self.add_outbound(ob):
                    added += 1
            if added == len(limited_obs):
                add_log(
                    "INFO",
                    f"Applied {added}/{len(limited_obs)} proxies via API (total working: {proxy_count})",
                )
            else:
                add_log(
                    "WARN",
                    f"Only {added}/{len(limited_obs)} outbound adds succeeded via API — restarting Xray",
                )
                self._write_and_restart(cfg_path, max_active)
        else:
            self._write_and_restart(cfg_path, max_active)
        self._update_subscribe_cache()

    def _write_and_restart(self, cfg_path, max_active, attempt=1, skip_geosite=False):
        """Пишет конфиг на диск и перезапускает Xray. При неудаче пробует без geosite."""
        limited = self.generate_full_config(
            max_outbounds=max_active, skip_geosite=skip_geosite
        )
        rule_count = len(self._geosite_rules())
        cfg_path.write_text(json.dumps(limited, indent=2))
        applied = sum(1 for o in limited["outbounds"] if o["tag"].startswith("node"))
        all_working = db_q("SELECT COUNT(*) c FROM proxies WHERE status='working'")[0][
            "c"
        ]
        add_log(
            "WARN" if attempt > 1 else "INFO",
            f"Xray API unavailable — wrote {applied} proxies to disk (total working: {all_working})",
        )
        if applied == 0:
            return
        add_log("INFO", "Restarting Xray to enable API services...")
        self.restart_via_systemd()
        # Ждём и проверяем, взлетел ли Xray (с повторными попытками)
        import time

        for wait in (5, 10, 15):
            time.sleep(wait)
            if self.api_ok():
                return
        if rule_count > 0 and attempt < 2:
            add_log(
                "WARN",
                "Xray failed to start with GeoSite rules — retrying without them",
            )
            self._write_and_restart(cfg_path, max_active, attempt=2, skip_geosite=True)
        else:
            self._log_systemd_xray_error()

    @staticmethod
    def _log_systemd_xray_error():
        """Логирует последние строки из journalctl для xray (только ошибки/предупреждения/старт)."""
        add_log(
            "ERROR", "Xray still not running after restart — check journalctl -u xray"
        )
        try:
            r = subprocess.run(
                ["journalctl", "-u", "xray", "--no-pager", "-n", "20", "-p", "err"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if r.stdout:
                for line in r.stdout.strip().splitlines()[-10:]:
                    line = line.strip()
                    if line:
                        add_log("ERROR", f"systemd: {line}")
        except Exception as e:
            add_log("DEBUG", f"Failed to capture journalctl: {e}")

    # ─── Subscribe cache ───

    def _update_subscribe_cache(self):
        """Собирает subscribe.txt с vless-ссылками + метаданными для внешних клиентов."""
        try:
            max_active = Settings.max_active_proxies()
            allowed = Settings.allowed_countries()
            codes = (
                [c.strip() for c in allowed.split(",") if c.strip()] if allowed else []
            )
            if codes:
                placeholders = ",".join("?" * len(codes))
                country_sql = f"AND country IN ({placeholders})"
            else:
                placeholders = ""
                country_sql = ""
                codes = []
            sort_col = "speed_kbps > 0 DESC, speed_kbps DESC, latency_vless ASC"
            rows = db_q(
                f"SELECT link, country, speed_kbps FROM proxies WHERE status='working' AND latency_vless > 0 {country_sql} ORDER BY {sort_col} LIMIT ?",
                codes + [max_active],
            )
            total_all = db_q("SELECT COUNT(*) c FROM proxies")[0]["c"]
            total_working = db_q(
                "SELECT COUNT(*) c FROM proxies WHERE status='working'"
            )[0]["c"]
            avg_speed = db_q(
                "SELECT CAST(AVG(speed_kbps) AS INTEGER) a FROM proxies WHERE status='working' AND speed_kbps > 0"
            )[0]["a"]
            probe_url = Settings.probe_url()
            now = moscow_str()
            lines = [
                "# profile-title: VLESS Manager",
                "# profile-update-interval: 1",
                f"# Updated: {now}",
                f"# Configs: {len(rows)} / {total_working} working / {total_all} total",
            ]
            if avg_speed:
                speed_str = (
                    f"{avg_speed // 1000}.{avg_speed % 1000 // 100} Mbps"
                    if avg_speed >= 1000
                    else f"{avg_speed} Kbps"
                )
                lines.append(f"# Avg speed: {speed_str}")
            if allowed:
                lines.append(f"# Filter: {allowed}")
            lines.append(f"# Probe: {probe_url}")
            lines.append("")
            for r in rows:
                link = r["link"]
                if "#" not in link:
                    host_part = (
                        link.split("@")[1].split("?")[0].split(":")[0]
                        if "@" in link
                        else ""
                    )
                    name = host_part[:20]
                    if r["country"]:
                        name = f"{r['country']}_{name}"
                    link = f"{link}#{name}"
                lines.append(link)
            SUBSCRIBE_FILE.write_text("\n".join(lines), encoding="utf-8")
            add_log("DEBUG", f"Subscribe cache updated: {len(rows)} proxies")
        except Exception as e:
            add_log("ERROR", f"Failed to update subscribe cache: {e}")

    # ─── Diagnosis ───

    @staticmethod
    def _detect_systemd_config():
        """Извлекает путь к конфигу Xray из systemd unit (ExecStart)."""
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
        except Exception as e:
            add_log("WARN", f"Failed to detect systemd xray config path: {e}")
        return None

    @staticmethod
    def _systemd_active():
        """Проверяет, активен ли systemd-сервис xray."""
        try:
            r = subprocess.run(
                ["systemctl", "is-active", "xray"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            return r.stdout.strip() == "active"
        except Exception as e:
            add_log("DEBUG", f"Failed to check systemd active: {e}")
            return False

    @staticmethod
    def _ss_listen(port):
        """Проверяет, слушает ли процесс указанный TCP-порт (через ss)."""
        try:
            r = subprocess.run(
                ["ss", "-lntp"], capture_output=True, text=True, timeout=3
            )
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
                {
                    "protocol": ib.get("protocol"),
                    "port": ib.get("port"),
                    "listen": ib.get("listen"),
                }
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
