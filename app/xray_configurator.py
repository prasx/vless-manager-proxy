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
from .subscribe import update_subscribe_cache
from .vless import parse_vless, stream_settings, sanitize_flow
from config import SOCKS_PORT, HTTP_PORT, API_PORT, API_LISTEN


class XrayConfigurator:
    """Управление конфигурацией Xray: генерация, применение через API, диагностика."""

    def __init__(self):
        self._apply_lock = threading.Lock()
        self._last_config_hash = ""
        self._last_restart_time = 0.0
        self._restart_cooldown = 120  # seconds
        self._stats_cache = {"data": None, "ts": 0.0}
        self._stats_cache_lock = threading.Lock()

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
        has_balancer=False — правило proxy → direct (нет рабочих прокси).
        Правила с префиксом geoip: попадают в поле ip, остальные — в domain."""
        if not cls._geosite_available_check():
            return []
        rules = []
        for item in Settings.geosite_rules():
            domain = (item.get("domain") or "").strip()
            tag = (item.get("outboundTag") or "").strip()
            if not domain:
                continue
            is_geoip = domain.startswith("geoip:")
            rule = {"type": "field"}
            if is_geoip:
                rule["ip"] = [domain]
            else:
                rule["domain"] = [domain]
            if tag == "proxy":
                if has_balancer:
                    rule["balancerTag"] = "auto"
                else:
                    rule["outboundTag"] = "direct"
            elif tag == "direct":
                rule["outboundTag"] = "direct"
            else:
                continue
            rules.append(rule)
        return rules

    # ─── Config generation ───

    @staticmethod
    def _policy_config() -> dict:
        """Политика таймаутов для Xray."""
        return {
            "levels": {
                "0": {
                    "handshake": int(Settings.get("handshake_timeout", "8")),
                    "connIdle": int(Settings.get("conn_idle", "300")),
                }
            }
        }

    @staticmethod
    def _inbounds_config() -> list:
        """SOCKS, HTTP и API inbounds."""
        return (
            XrayConfigurator._proxy_inbounds(Settings.proxy_listen())
            + [
                {
                    "listen": API_LISTEN,
                    "port": API_PORT,
                    "protocol": "dokodemo-door",
                    "settings": {"address": API_LISTEN},
                    "tag": "api",
                }
            ]
        )

    @staticmethod
    def _api_config() -> dict:
        return {"tag": "api", "services": ["HandlerService", "RoutingService", "StatsService"]}

    @staticmethod
    def _geo_routing_rules(skip_geosite: bool = False, has_balancer: bool = True) -> list:
        """Возвращает geoip + geosite routing rules."""
        if Settings.get("geo_enabled", "true") != "true":
            return []
        rules: list = [
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
            {"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"},
        ]
        if not skip_geosite:
            rules.extend(XrayConfigurator._geosite_rules(has_balancer=has_balancer))
        return rules

    def generate_full_config(self, max_outbounds: int = 0, skip_geosite: bool = False) -> dict:
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
        else:
            rows = db_q(
                f"SELECT link FROM proxies WHERE status='working' AND latency_vless > 0 {country_sql}",
                codes,
            )
        for r in rows:
            parsed = parse_vless(r["link"])
            if parsed:
                proxy_obs.append(self._build_outbound(parsed, f"node{len(proxy_obs)}"))

        has_proxies = bool(proxy_obs)
        routing_rules: list = [
            {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
            {"inboundTag": ["api"], "outboundTag": "api"},
        ]
        routing_rules.extend(self._geo_routing_rules(skip_geosite=skip_geosite, has_balancer=has_proxies))
        if has_proxies:
            routing_rules.append({"type": "field", "network": "tcp,udp", "balancerTag": "auto"})
        else:
            routing_rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "direct"})

        config = {
            "api": self._api_config(),
            "log": {"loglevel": "warning"},
            "inbounds": self._inbounds_config(),
            "outbounds": proxy_obs + [
                {"protocol": "freedom", "tag": "direct"},
                {"protocol": "freedom", "tag": "api"},
            ],
            "routing": {"domainStrategy": "IPIfNonMatch", "rules": routing_rules},
            "policy": self._policy_config(),
        }
        if has_proxies:
            config["observatory"] = {
                "subjectSelector": ["node"],
                "probeUrl": Settings.probe_url(),
                "probeInterval": Settings.get("observatory_probe_interval", "15s"),
                "enableConcurrency": True,
            }
            config["routing"]["balancers"] = [
                {
                    "tag": "auto",
                    "selector": ["node"],
                    "strategy": {"type": Settings.get("balancer_strategy", "random")},
                }
            ]
        return self._inject_api(config)

    def generate_base_config(self) -> dict:
        """Минимальный конфиг для диска — прокси управляются только через API."""
        geo_rules = self._geo_routing_rules(has_balancer=False)
        catch_all = {"type": "field", "network": "tcp,udp", "outboundTag": "direct"}
        base = {
            "api": self._api_config(),
            "log": {"loglevel": "warning"},
            "inbounds": self._inbounds_config(),
            "outbounds": [
                {"protocol": "freedom", "tag": "direct"},
                {"protocol": "freedom", "tag": "api"},
            ],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [
                    {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
                    {"inboundTag": ["api"], "outboundTag": "api"},
                ]
                + geo_rules
                + [catch_all],
            },
            "policy": self._policy_config(),
        }
        return self._inject_api(base)

    # ─── Xray API helpers ───

    def _cached_statsquery(self, ttl=10):
        """Возвращает кэшированный результат `xray api statsquery`.
        Кэш живёт ttl секунд. Возвращает (returncode, stdout) или (-1, '')."""
        now = time.time()
        with self._stats_cache_lock:
            if self._stats_cache["data"] and (now - self._stats_cache["ts"]) < ttl:
                return self._stats_cache["data"]
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
            data = (r.returncode, r.stdout)
        except Exception as e:
            add_log("DEBUG", f"statsquery failed: {e}")
            data = (-1, "")
        with self._stats_cache_lock:
            self._stats_cache["data"] = data
            self._stats_cache["ts"] = now
        return data

    def api_ok(self):
        """Проверяет, отвечает ли Xray API (использует кэш statsquery)."""
        try:
            s = socket.create_connection((API_LISTEN, API_PORT), timeout=2)
            s.close()
        except Exception:
            return False
        rc, _ = self._cached_statsquery()
        return rc == 0

    def list_active_outbounds(self):
        """Возвращает список тегов активных outbound (использует кэш statsquery)."""
        rc, out = self._cached_statsquery()
        if rc != 0:
            return []
        tags = set()
        for line in out.splitlines():
            m = re.search(r"outbound>>>([^>]+)>>>traffic>>>([a-z]+)", line)
            if m:
                tags.add(m.group(1))
        return sorted(tags)

    @staticmethod
    def _remove_outbound(tag):
        """Удаляет один outbound по тегу через Xray API."""
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

    def remove_all_outbounds(self):
        """Удаляет все node* outbound из Xray через API."""
        for tag in self.list_active_outbounds():
            if tag.startswith("node"):
                XrayConfigurator._remove_outbound(tag)

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
                Settings.get("observatory_probe_interval", "15s"),
                Settings.get("balancer_strategy", "random"),
                Settings.get("handshake_timeout", "8"),
                Settings.get("conn_idle", "300"),
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
            domains = [
                r.get("domain", r.get("ip", [""]))[0]
                for r in geosite_rules_list
                if "domain" in r or "ip" in r
            ]
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

            # Cooldown после рестарта: не дёргаем API, даём Xray устаканиться
            since_restart = time.time() - self._last_restart_time
            if since_restart < self._restart_cooldown:
                add_log(
                    "INFO",
                    f"Restart cooldown ({self._restart_cooldown - since_restart:.0f}s left) — skipping API hot-reload, config on disk",
                )
                return

            # Удаляем все старые node* outbound и добавляем новые
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
            elif added == 0:
                add_log(
                    "WARN",
                    f"All {len(limited_obs)} outbound adds failed via API — restarting Xray to reload config from disk",
                )
                self.restart_via_systemd()
                self._last_restart_time = time.time()
                for wait in (5, 10, 15):
                    time.sleep(wait)
                    if self.api_ok():
                        break
            else:
                add_log(
                    "WARN",
                    f"Only {added}/{len(limited_obs)} outbound adds succeeded via API — config on disk is intact for next cycle",
                )
        else:
            self._write_and_restart(cfg_path, max_active)
        update_subscribe_cache()

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
        self._last_restart_time = time.time()
        # Ждём и проверяем, взлетел ли Xray (с повторными попытками)
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
