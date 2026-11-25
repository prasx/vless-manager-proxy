"""Генерация конфига Xray, горячее применение через API, диагностика, подписка."""

import json
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from .db import Settings, xray_config_path
from .utils import add_log
from .subscribe import update_subscribe_cache
from .vless import stream_settings, sanitize_flow
from .selection import config_rows, node_tag
from config import API_LISTEN

# Кэши диагностики: страница настроек опрашивает /api/xray/status каждые 5 с,
# и каждый такой запрос дёргал systemctl/ss и писал WARN в логи (на Windows без
# systemd это давало десятки записей в минуту). Значения меняются редко.
_SYSTEMD_CFG_TTL = 120.0
_SYSTEMD_ACTIVE_TTL = 10.0
_SS_LISTEN_TTL = 15.0
_DIAG_TTL = 8.0
_diag_cache: dict = {"systemd_cfg": (0.0, None), "active": (0.0, None)}
_diag_cache_lock = threading.Lock()
_ss_cache: dict[int, tuple[float, str | None]] = {}
_ss_cache_lock = threading.Lock()


def _ensure_duration(val: str, default: str = "10s") -> str:
    """Гарантирует, что строка — валидный Go duration (имеет суффикс s/ms/m/h)."""
    val = (val or "").strip()
    if not val:
        return default
    if val[-1].isdigit():
        val += "s"
    return val


class XrayConfigurator:
    """Управление конфигурацией Xray: генерация, применение через API, диагностика."""

    APPLY_LOCK_TIMEOUT = 120.0

    def __init__(self):
        """Инициализирует блокировки и кэши состояния Xray."""
        self._apply_lock = threading.Lock()
        self._last_restart_time = 0.0
        self._restart_cooldown = 20  # seconds
        # Последний результат применения: нужен UI, чтобы показать
        # «конфиг на диске новее живого Xray», а не терять это в логах.
        self._apply_state_lock = threading.Lock()
        self._last_apply: dict = {}
        # Снимок применённого набора outbound уже снят (см. _init_applied_state).
        self._state_ready = False
        self._stats_cache = {"data": None, "ts": 0.0}
        self._stats_cache_lock = threading.Lock()
        # lso (ListOutbounds) — авторитетный список живых outbound. Старый
        # statsquery оставляет счётчики удалённых узлов, поэтому как основной
        # источник он не годится.
        self._lso_cache = {"data": None, "ts": 0.0}
        self._lso_cache_lock = threading.Lock()
        self._lso_supported: bool | None = None
        self._live_source = ""
        self._diag_result_cache = {"data": None, "ts": 0.0}
        self._diag_result_lock = threading.Lock()

    # ─── Inbounds / Base config helpers ───

    @staticmethod
    def _proxy_inbounds(listen):
        """Возвращает SOCKS и HTTP inbound для заданного адреса прослушивания."""
        sniffing_enabled = Settings.get("sniffing_enabled", "true") == "true"
        sniffing_dest = Settings.get("sniffing_dest_override", "http,tls")
        sniffing_route = Settings.get("sniffing_route_only", "true") == "true"
        dest_override = [s.strip() for s in sniffing_dest.split(",") if s.strip()]

        sniffing = {}
        if sniffing_enabled and dest_override:
            sniffing = {
                "enabled": True,
                "destOverride": dest_override,
                "routeOnly": sniffing_route,
            }

        socks_in = {
            "port": Settings.socks_port(),
            "listen": listen,
            "protocol": "socks",
            "settings": {"udp": True},
            "stats": {"enabled": True},
        }
        if sniffing:
            socks_in["sniffing"] = sniffing

        http_in = {
            "port": Settings.http_port(),
            "listen": listen,
            "protocol": "http",
            "settings": {},
            "stats": {"enabled": True},
        }
        if sniffing:
            http_in["sniffing"] = sniffing

        return [socks_in, http_in]

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
            "port": Settings.api_port(),
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
            "stats": {"enabled": True},
        }
        flow = sanitize_flow(parsed.get("flow"))
        if flow:
            ob["settings"]["vnext"][0]["users"][0]["flow"] = flow
        return ob

    _geosite_checked = False
    _geosite_available = False

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
        """Политика таймаутов + статистика для Xray."""
        return {
            "levels": {
                "0": {
                    "handshake": int(Settings.get("handshake_timeout")),
                    "connIdle": int(Settings.get("conn_idle", "300")),
                }
            },
            "system": {
                "statsInboundDownlink": True,
                "statsInboundUplink": True,
                "statsOutboundDownlink": True,
                "statsOutboundUplink": True,
            },
        }

    @staticmethod
    def _inbounds_config() -> list:
        """SOCKS, HTTP и API inbounds."""
        return (
            XrayConfigurator._proxy_inbounds(Settings.proxy_listen())
            + [
                {
                    "listen": API_LISTEN,
                    "port": Settings.api_port(),
                    "protocol": "dokodemo-door",
                    "settings": {"address": API_LISTEN},
                    "tag": "api",
                    "stats": {"enabled": True},
                }
            ]
        )

    @staticmethod
    def _api_config() -> dict:
        """Outbound-заглушка для API и список сервисов Xray."""
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

    @staticmethod
    def select_nodes(max_outbounds: int = 0):
        """Отбор профилей по единой политике (см. app/selection.py)."""
        return config_rows(max_outbounds)

    def _log_selection(self, sel):
        """Пишет в лог, сколько профилей отобрано и что отсеяно."""
        add_log("DEBUG", f"Config selection: {sel.summary()}")
        if sel.fallback == "slow":
            add_log(
                "WARN",
                "Config fallback: все замеренные профили медленнее порога — "
                "в конфиг временно идут они. Снизьте min_speed_mbps или найдите узлы быстрее",
            )
        elif sel.fallback == "unmeasured":
            add_log(
                "WARN",
                "Config fallback: ни один профиль не замерен по скорости — "
                "в конфиг временно идут незамеренные. Проверьте speed_test_url "
                "и стадию замера скорости",
            )
        elif sel.fallback == "stale":
            add_log(
                "WARN",
                f"Config fallback: нет свежих профилей (порог {sel.fresh_minutes} мин) — "
                "временно используются устаревшие. Запустите «Тест всех»",
            )
        elif sel.strict and not sel.rows:
            add_log(
                "WARN",
                "Strict selection: включён режим «только замеренные», но замеренных "
                "свежих профилей нет — конфиг и подписка пусты",
            )
        elif not sel.rows:
            add_log("WARN", "Config selection is empty: нет ни одного профиля для конфига")

    def generate_full_config(
        self, max_outbounds: int = 0, skip_geosite: bool = False, selection=None
    ) -> dict:
        """Генерирует полный конфиг с observatory + balancer.

        Если max_outbounds > 0 — только N самых приоритетных outbound.
        Отбор профилей — единая политика app/selection.py: рабочие, свежие,
        с приоритетом замеренных. selection передаётся, если вызывающий уже
        сделал отбор (чтобы не считать его дважды).
        skip_geosite=True — временно исключить geosite-правила (для recovery).
        """
        sel = selection if selection is not None else self.select_nodes(max_outbounds)
        proxy_obs = []
        for r in sel.rows:
            parsed = r.get("parsed")
            if not parsed:
                continue
            proxy_obs.append(self._build_outbound(parsed, node_tag(r["id"])))

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
            "stats": {},
            "inbounds": self._inbounds_config(),
            "outbounds": proxy_obs + [
                {"protocol": "freedom", "tag": "direct", "stats": {"enabled": True}},
                {"protocol": "freedom", "tag": "api", "stats": {"enabled": True}},
            ],
            "routing": {"domainStrategy": "IPIfNonMatch", "rules": routing_rules},
            "policy": self._policy_config(),
        }
        if has_proxies:
            config["observatory"] = {
                "subjectSelector": ["node"],
                "probeUrl": Settings.probe_url(),
                "probeInterval": _ensure_duration(Settings.get("observatory_probe_interval")),
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
                    f"{API_LISTEN}:{Settings.api_port()}",
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
            s = socket.create_connection((API_LISTEN, Settings.api_port()), timeout=2)
            s.close()
        except Exception:
            return False
        rc, _ = self._cached_statsquery()
        return rc == 0

    def list_active_outbounds(self):
        """Возвращает список тегов outbound, по которым есть счётчики трафика.

        Это не список живых обработчиков: statsquery хранит счётчики и после
        `rmo`. Для фактического набора используйте live_node_tags()/lso.
        """
        rc, out = self._cached_statsquery()
        if rc != 0:
            return []
        tags = set()
        for line in out.splitlines():
            m = re.search(r"outbound>>>([^>]+)>>>traffic>>>([a-z]+)", line)
            if m:
                tags.add(m.group(1))
        return sorted(tags)

    def _list_outbounds_lso(self, force: bool = False) -> set[str] | None:
        """Список реально зарегистрированных outbound через `xray api lso`.

        None — команда недоступна/не ответила; пустое множество — валидный
        ответ «outbound'ов нет».
        """
        if self._lso_supported is False:
            return None
        now = time.time()
        with self._lso_cache_lock:
            cached = self._lso_cache["data"]
            if not force and cached is not None and now - self._lso_cache["ts"] < 3:
                return cached
        try:
            r = subprocess.run(
                [
                    Settings.xray_bin(),
                    "api",
                    "lso",
                    "-s",
                    f"{API_LISTEN}:{Settings.api_port()}",
                ],
                capture_output=True,
                text=True,
                timeout=6,
            )
        except Exception as e:  # noqa: BLE001
            # Таймаут/недоступный API — не повод навсегда отключать lso:
            # следующий вызов попробует снова.
            add_log("DEBUG", f"lso unavailable: {e}")
            return None
        if r.returncode != 0:
            detail = (r.stderr or r.stdout or "").strip()[:200]
            if any(word in detail.lower() for word in ("unknown command", "flag provided", "not defined")):
                self._lso_supported = False
            add_log("DEBUG", f"lso unavailable (code {r.returncode}): {detail}")
            return None
        try:
            data = json.loads(r.stdout or "{}")
            outbounds = data.get("outbounds") if isinstance(data, dict) else data
            tags = {
                ob.get("tag")
                for ob in (outbounds or [])
                if isinstance(ob, dict) and isinstance(ob.get("tag"), str)
            }
        except (ValueError, TypeError) as e:
            self._lso_supported = False
            add_log("DEBUG", f"lso response parse failed: {e}")
            return None
        self._lso_supported = True
        result = {t for t in tags if t.startswith("node")}
        with self._lso_cache_lock:
            self._lso_cache = {"data": result, "ts": now}
        return result

    def live_source(self) -> str:
        """Источник последнего live-набора: lso, statsquery или пусто."""
        return self._live_source

    @staticmethod
    def _remove_outbounds(tags) -> set[str]:
        """Удаляет node-outbound по тегам через Xray API (`rmo`).

        Синтаксис `xray api rmo <tag> [tag...]` — позиционный. Код раньше
        передавал `--tag`, и КАЖДОЕ удаление падало с «flag provided but not
        defined: -tag»: старые узлы оставались в Xray, а добавление новых тегов
        падало с «existing tag found». Отсюда был вечный цикл «частично
        применено → пересборка → рестарт Xray». Теги принимаются пачкой:
        один вызов CLI вместо десятков.
        """
        tags = [t for t in dict.fromkeys(tags or []) if t]
        if not tags:
            return set()
        removed: set[str] = set()
        cmd = [
            Settings.xray_bin(),
            "api",
            "rmo",
            "-s",
            f"{API_LISTEN}:{Settings.api_port()}",
            *tags,
        ]
        try:
            r = subprocess.run(
                cmd, capture_output=True, timeout=max(10, min(60, 3 * len(tags)))
            )
            if r.returncode == 0:
                return set(tags)
            add_log(
                "DEBUG",
                f"Remove outbounds failed (code {r.returncode}): "
                f"{r.stderr.decode(errors='replace')[:300]}",
            )
        except Exception as e:  # noqa: BLE001
            add_log("DEBUG", f"Failed to remove outbounds {tags}: {e}")
            return set()

        # Старые версии Xray могли не понимать несколько тегов за раз:
        # пробуем по одному, чтобы хотя бы часть удалилась.
        for tag in tags:
            try:
                r = subprocess.run(
                    [
                        Settings.xray_bin(),
                        "api",
                        "rmo",
                        "-s",
                        f"{API_LISTEN}:{Settings.api_port()}",
                        tag,
                    ],
                    capture_output=True,
                    timeout=10,
                )
                if r.returncode == 0:
                    removed.add(tag)
                else:
                    add_log(
                        "DEBUG",
                        f"Remove outbound {tag} failed (code {r.returncode}): "
                        f"{r.stderr.decode(errors='replace')[:200]}",
                    )
            except Exception as e:  # noqa: BLE001
                add_log("DEBUG", f"Failed to remove outbound {tag}: {e}")
        return removed

    @staticmethod
    def add_outbound(ob):
        """Добавляет один outbound в Xray через API (26.x: ado)."""
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        with tmp:
            json.dump({"outbounds": [ob]}, tmp)
            tmp_path = tmp.name
        ok = False
        try:
            r = subprocess.run(
                [
                    Settings.xray_bin(),
                    "api",
                    "ado",
                    "-s",
                    f"{API_LISTEN}:{Settings.api_port()}",
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

    def restart_via_systemd(self):
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
                # Xray поднялся с конфигом на диске — это и есть применённый набор.
                disk = self._disk_node_tags()
                if disk:
                    Settings.set_applied_node_tags(disk)
                self._last_restart_time = time.time()
                return True
            add_log("WARN", f"systemctl restart xray failed: {r.stderr.decode()[:200]}")
        except Exception as e:
            add_log("WARN", f"Could not restart systemd xray: {e}")
        return False

    # ─── Применённое состояние outbound ───

    def live_node_tags(self, force: bool = False) -> set[str]:
        """node-теги, реально зарегистрированные в работающем Xray.

        Основной источник — `xray api lso` (ListOutbounds). statsquery
        используется только как fallback: его счётчики остаются и после
        удаления outbound, поэтому по ним нельзя надёжно определить живой набор.
        Пустой ответ lso — это валидное «outbound'ов нет».
        """
        if not self.api_ok():
            self._live_source = ""
            return set()
        tags = self._list_outbounds_lso(force=force)
        if tags is not None:
            self._live_source = "lso"
            return tags
        self._live_source = "statsquery"
        return {t for t in self.list_active_outbounds() if t.startswith("node")}

    def _disk_node_tags(self) -> set[str]:
        """node-теги из конфига на диске (с ним Xray стартовал/стартует)."""
        try:
            data = json.loads(xray_config_path().read_text())
            return {
                ob["tag"]
                for ob in data.get("outbounds", [])
                if isinstance(ob.get("tag"), str) and ob["tag"].startswith("node")
            }
        except Exception:
            return set()

    def disk_node_tags(self) -> set[str]:
        """Публичный снимок node-тегов из конфига на диске (для API/UI)."""
        return self._disk_node_tags()

    def desired_node_tags(self) -> set[str]:
        """node-теги, которые должны быть в конфиге по текущей политике отбора."""
        try:
            sel = self.select_nodes(Settings.max_active_proxies())
            return {node_tag(r["id"]) for r in sel.rows}
        except Exception as e:  # noqa: BLE001
            add_log("DEBUG", f"Desired outbound state failed: {e}")
            return set()

    def apply_state(self) -> dict:
        """Последний результат apply_all для API/UI."""
        with self._apply_state_lock:
            return dict(self._last_apply)

    def _record_apply(self, **fields) -> None:
        """Сохраняет последний результат apply для API/UI."""
        fields.setdefault("ts", time.time())
        with self._apply_state_lock:
            self._last_apply = dict(fields)

    def known_node_tags(self) -> set[str]:
        """Набор node-тегов, который, по нашим данным, уже живёт в Xray.

        Приоритет: живые счётчики statsquery → память панели. Конфиг на диске
        здесь не используется: к этому моменту мы уже могли перезаписать его
        новым набором, и «на диске есть» не значит «в работающем Xray есть».
        Начальное состояние снимается ДО записи конфига (_init_applied_state).
        """
        live = self.live_node_tags()
        if live:
            stored = set(Settings.applied_node_tags())
            if stored and stored != live:
                add_log(
                    "DEBUG",
                    f"Outbound state drift: память {len(stored)} vs живых {len(live)} тегов — верим statsquery",
                )
            Settings.set_applied_node_tags(live)
            return live
        return set(Settings.applied_node_tags())

    def _init_applied_state(self) -> None:
        """Снимает состояние outbound один раз перед первой записью конфига.

        Пока мы не перезаписали файл, он всё ещё описывает то, с чем Xray
        стартовал, поэтому именно он — лучшая догадка о живом наборе, когда
        statsquery молчит (счётчиков ещё нет). После записи файла эта догадка
        была бы уже ложной.
        """
        if self._state_ready:
            return
        self._state_ready = True
        live = self.live_node_tags()
        if live:
            Settings.set_applied_node_tags(live)
            return
        if not Settings.applied_node_tags():
            disk = self._disk_node_tags()
            if disk:
                Settings.set_applied_node_tags(disk)
                add_log("DEBUG", f"Applied outbound state initialised from disk config: {len(disk)} nodes")

    def _sync_outbounds(self, desired_obs) -> dict:
        """Diff-based синхронизация node* outbound через Xray API.

        Тег — `node<id профиля>`, поэтому тег однозначно связан с содержимым:
        пересортировка профилей после замера скорости больше не превращает
        node0 в другой узел (раньше diff-синк видел «тег есть» и не переотправлял
        outbound — в работающем Xray оставались старые адреса).

        Возвращает счётчики; решение о рестарте принимает вызывающий.
        """
        desired_tags = {ob["tag"] for ob in desired_obs}
        known = self.known_node_tags()
        to_remove = sorted(known - desired_tags)
        to_add = [ob for ob in desired_obs if ob["tag"] not in known]

        # Сначала удаляем лишние: иначе `ado` падает с «existing tag found»,
        # если тег остался в Xray после прошлых неудачных удалений.
        removed = self._remove_outbounds(to_remove) if to_remove else set()

        added: list[str] = []
        failed: list[str] = []
        for ob in to_add:
            if self.add_outbound(ob):
                added.append(ob["tag"])
                continue
            # Тег мог остаться в работающем Xray (память панели разошлась с
            # реальностью): убираем его и пробуем добавить ещё раз.
            if self._remove_outbounds([ob["tag"]]):
                removed.add(ob["tag"])
                if self.add_outbound(ob):
                    added.append(ob["tag"])
                    # Тег снова в Xray — значит, он не «удалён».
                    removed.discard(ob["tag"])
                    continue
            failed.append(ob["tag"])

        applied = (known | set(added)) - removed
        if applied != known or failed:
            Settings.set_applied_node_tags(applied)
        return {
            "added": len(added),
            "attempted": len(to_add),
            "failed": failed,
            "removed": len(removed),
            "total": len(desired_obs),
        }

    # ─── Apply config ───

    def apply_all(self, blocking=False, timeout: float | None = None):
        """Пишет полный конфиг на диск, прокси добавляет через Xray API.

        blocking=True — ждать освобождения _apply_lock, но не дольше
        APPLY_LOCK_TIMEOUT (120 с). Раньше ожидание было вечным: зависший
        промежуточный apply останавливал финальный и весь прогон.
        blocking=False — пропустить, если другой apply уже выполняется.
        Возвращает True, если конфиг обработан и живой набор подтверждён.
        """
        wait = self.APPLY_LOCK_TIMEOUT if timeout is None else max(0.0, float(timeout))
        if blocking:
            acquired = self._apply_lock.acquire(timeout=wait)
        else:
            acquired = self._apply_lock.acquire(blocking=False)
        if not acquired:
            if blocking:
                msg = (
                    f"Config rebuild: не дождался lock {wait:.0f}с — "
                    "конфиг на диске мог обновиться, живой Xray не подтверждён"
                )
                status = "lock_timeout"
            else:
                msg = "Config rebuild already in progress — skipping"
                status = "busy"
            add_log("WARN", msg)
            prev = self.apply_state()
            self._record_apply(
                ok=False,
                status=status,
                message=msg,
                config_on_disk_newer=(status == "lock_timeout"),
                desired_tags=prev.get("desired_tags", []),
                live_tags=prev.get("live_tags", []),
                disk_tags=prev.get("disk_tags", []),
            )
            return False
        try:
            result = self._apply_all_impl()
            if not isinstance(result, dict):
                result = {"ok": True, "status": "applied"}
            return bool(result.get("ok", False))
        finally:
            self._apply_lock.release()

    def _apply_all_impl(self):
        """Внутренняя реализация применения конфига (без блокировки)."""
        try:
            return self._apply_all_impl_safe()
        except Exception as e:
            hint = ""
            if isinstance(e, PermissionError):
                hint = (
                    f" — нет прав на запись файла конфига. Проверьте владельца/права "
                    f"на {xray_config_path()} (панель должна писать туда, откуда "
                    f"Xray читает конфиг)"
                )
            msg = f"Config rebuild failed: {e}{hint}"
            add_log("ERROR", msg)
            self._record_apply(
                ok=False,
                status="exception",
                message=msg,
                config_on_disk_newer=True,
            )
            return {"ok": False, "status": "exception", "message": msg}

    def _apply_all_impl_safe(self):
        """Пишет конфиг/подписку и синхронизирует outbound; не бросает наружу."""
        cfg_path = xray_config_path()
        cfg_path.parent.mkdir(parents=True, exist_ok=True)

        # До перезаписи файла: снимок того, с чем Xray реально стартовал.
        self._init_applied_state()

        max_active = Settings.max_active_proxies()
        sel = self.select_nodes(max_active)
        self._log_selection(sel)

        full = self.generate_full_config(selection=sel)
        limited_obs = [o for o in full["outbounds"] if o["tag"].startswith("node")]

        # Всегда пишем конфиг на диск (нужен для systemd-рестарта и диагностики)
        cfg_path.write_text(json.dumps(full, indent=2))
        add_log("DEBUG", f"Config written to disk ({len(limited_obs)} outbounds)")
        # Подписка не зависит от того, применился ли hot-reload: обновляем сразу.
        # Раньше при cooldown после рестарта подписка оставалась старой.
        update_subscribe_cache()

        has_work = bool(limited_obs)
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

        desired_tags = {o["tag"] for o in limited_obs}

        def finish(status, ok, message, *, live=None, config_newer=False, **extra):
            """Формирует и сохраняет итоговое состояние apply."""
            live_set = set(live or [])
            state = {
                "ok": bool(ok),
                "status": status,
                "message": message,
                "desired_tags": sorted(desired_tags),
                "live_tags": sorted(live_set),
                "disk_tags": sorted(self._disk_node_tags()),
                "config_on_disk_newer": bool(config_newer),
                "live_unknown": (not live_set and self._live_source != "lso"),
                "live_source": self._live_source,
                **extra,
            }
            self._record_apply(**state)
            return state

        if not self.api_ok():
            res = self._write_and_restart(cfg_path, max_active, selection=sel)
            live = self.live_node_tags(force=True)
            state = finish(
                res.get("status", "restarted" if res.get("ok") else "restart_failed"),
                bool(res.get("ok")),
                res.get("message", ""),
                live=live,
                config_newer=bool(res.get("config_on_disk_newer")),
                applied=res.get("applied", 0),
                desired=len(desired_tags),
            )
            return state

        # Cooldown после рестарта: не дёргаем API, даём Xray устаканиться
        since_restart = time.time() - self._last_restart_time
        if since_restart < self._restart_cooldown:
            live = self.live_node_tags()
            same = bool(live) and live == desired_tags
            msg = (
                f"Restart cooldown ({self._restart_cooldown - since_restart:.0f}s left) — "
                "API hot-reload deferred"
            )
            add_log("WARN" if desired_tags and not same else "INFO", msg)
            if desired_tags and not same:
                add_log(
                    "WARN",
                    "Config on disk is newer than the live Xray set: "
                    f"desired {len(desired_tags)}, live {len(live)} — "
                    "will retry after cooldown",
                )
            return finish(
                "cooldown",
                same or not desired_tags,
                msg,
                live=live,
                config_newer=bool(desired_tags and not same),
            )

        result = self._sync_outbounds(limited_obs)
        live = self.live_node_tags(force=True)
        live_known = self._live_source == "lso"
        failed = result["failed"]
        added = result["added"]
        attempted = result["attempted"]
        removed = result["removed"]

        if attempted == 0 and removed == 0:
            if live_known and live != desired_tags:
                msg = (
                    "Outbound API reported no changes, но живой набор отличается: "
                    f"желаемых {len(desired_tags)}, живых {len(live)}"
                )
                add_log("WARN", msg)
                restarted, live_after = self._restart_after_mismatch(desired_tags)
                if restarted and live_after == desired_tags:
                    return finish(
                        "restarted", True, "Xray restarted to remove stale outbounds",
                        live=live_after, config_newer=False, added=added, failed=failed,
                        attempted=attempted,
                    )
                return finish(
                    "live_mismatch", False, msg, live=live_after or live,
                    config_newer=True, added=added, failed=failed, attempted=attempted,
                )
            add_log("DEBUG", f"All {result['total']} outbounds already in sync, no API calls needed")
            return finish(
                "in_sync", True, "All outbounds already in sync",
                live=live, config_newer=False, added=added, failed=failed,
                attempted=attempted,
            )

        if failed:
            msg = (
                f"Only {added}/{attempted} outbounds added via API — "
                f"{len(failed)} останутся в силе после рестарта Xray"
            )
            add_log("WARN", msg)
            # Если живых node-outbound не видно вовсе, Xray мог стартовать с пустым
            # конфигом: один рестарт применяет конфиг с диска. Не чаще раза в 5 мин,
            # чтобы не устраивать цикл рестартов.
            restarted = False
            if not live and time.time() - self._last_restart_time > 300:
                add_log("WARN", "No live node outbounds visible — restarting Xray to apply config from disk")
                restarted = self.restart_via_systemd()
                live = self.live_node_tags(force=True)
            if restarted and live:
                return finish(
                    "restarted", True, "Xray restarted after partial API apply",
                    live=live, config_newer=False, added=added, failed=failed,
                    attempted=attempted,
                )
            if restarted:
                return finish(
                    "restarted", True,
                    "Xray restarted after partial API apply; live set not visible yet",
                    live=live, config_newer=False, added=added, failed=failed,
                    attempted=attempted,
                )
            add_log(
                "WARN",
                "Config on disk is newer than the live Xray set: "
                f"desired {len(desired_tags)}, live {len(live)}, failed "
                f"{len(failed)} — нужен рестарт или повторный apply",
            )
            return finish(
                "partial", False, msg, live=live, config_newer=True,
                added=added, failed=failed, attempted=attempted,
            )

        if live_known and live != desired_tags:
            msg = (
                "API применил изменения, но живой набор всё ещё отличается: "
                f"желаемых {len(desired_tags)}, живых {len(live)}"
            )
            add_log("WARN", msg)
            add_log(
                "WARN",
                "Config on disk is newer than the live Xray set — "
                "restart Xray or apply again",
            )
            restarted, live_after = self._restart_after_mismatch(desired_tags)
            if restarted and live_after == desired_tags:
                return finish(
                    "restarted", True, "Xray restarted to remove stale outbounds",
                    live=live_after, config_newer=False, added=added, failed=failed,
                    attempted=attempted,
                )
            return finish(
                "live_mismatch", False, msg, live=live_after or live,
                config_newer=True, added=added, failed=failed, attempted=attempted,
            )

        msg = (
            f"Applied outbounds via API: +{added} / -{removed} "
            f"(total {result['total']}, измеренных "
            f"{sum(1 for r in sel.rows if r.get('tier') == 1)})"
        )
        add_log("INFO", msg)
        return finish(
            "applied", True, msg, live=live, config_newer=False,
            added=added, failed=failed, attempted=attempted,
        )

    def _restart_after_mismatch(self, desired_tags: set[str]):
        """Перезапускает Xray, если lso показал реальное расхождение.

        Возвращает (restarted, live_tags). Не чаще раза в 5 минут, чтобы
        повторный apply не устраивал цикл рестартов.
        """
        if time.time() - self._last_restart_time <= 300:
            return False, set()
        add_log(
            "WARN",
            "Live outbound set differs from disk — restarting Xray to apply disk config",
        )
        restarted = self.restart_via_systemd()
        live = self.live_node_tags(force=True)
        return restarted, live

    def _write_and_restart(self, cfg_path, max_active, attempt=1, skip_geosite=False, selection=None):
        """Пишет конфиг на диск и перезапускает Xray. При неудаче пробует без geosite."""
        sel = selection if (selection is not None and not skip_geosite) else self.select_nodes(max_active)
        if sel is not selection:
            self._log_selection(sel)
        limited = self.generate_full_config(selection=sel, skip_geosite=skip_geosite)
        rule_count = len(self._geosite_rules())
        cfg_path.write_text(json.dumps(limited, indent=2))
        applied = sum(1 for o in limited["outbounds"] if o["tag"].startswith("node"))
        add_log(
            "WARN" if attempt > 1 else "INFO",
            f"Xray API unavailable — wrote {applied} proxies to disk "
            f"(working {sel.counts.get('working_total', 0)}, годных {sel.counts.get('eligible', 0)})",
        )
        if applied == 0:
            msg = (
                "Config written with 0 node outbounds — Xray NOT restarted; "
                "старый живой набор остаётся, конфиг на диске новее"
            )
            add_log("WARN", msg)
            return {
                "ok": False,
                "status": "empty_config",
                "message": msg,
                "applied": 0,
                "config_on_disk_newer": True,
            }
        add_log("INFO", "Restarting Xray to enable API services...")
        restart_ok = self.restart_via_systemd()
        self._last_restart_time = time.time()
        # Ждём и проверяем, взлетел ли Xray (с повторными попытками)
        for wait in (5, 10, 15):
            time.sleep(wait)
            if self.api_ok():
                return {
                    "ok": True,
                    "status": "restarted",
                    "message": "Xray restarted with config from disk",
                    "applied": applied,
                    "config_on_disk_newer": False,
                }
        if rule_count > 0 and attempt < 2:
            add_log(
                "WARN",
                "Xray failed to start with GeoSite rules — retrying without them",
            )
            return self._write_and_restart(
                cfg_path, max_active, attempt=2, skip_geosite=True, selection=sel
            )
        self._log_systemd_xray_error()
        msg = (
            "Xray did not come up with the config from disk"
            if restart_ok else "systemctl restart xray failed"
        )
        return {
            "ok": False,
            "status": "restart_failed",
            "message": msg,
            "applied": applied,
            "config_on_disk_newer": True,
        }


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
        now = time.monotonic()
        with _diag_cache_lock:
            ts, cached = _diag_cache["systemd_cfg"]
        if ts and now - ts < _SYSTEMD_CFG_TTL:
            return cached
        value = None
        try:
            r = subprocess.run(
                ["systemctl", "show", "xray", "-p", "ExecStart", "--value"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if r.returncode == 0:
                text = r.stdout.strip()
                for flag in ("-config", "-c"):
                    if flag not in text:
                        continue
                    parts = text.replace("=", " ").split()
                    for i, p in enumerate(parts):
                        if p == flag and i + 1 < len(parts):
                            value = parts[i + 1]
                            break
                    if value:
                        break
        except Exception as e:
            # Windows/не-systemd окружения: это норма, а не ошибка — WARN
            # каждые 5 секунд только засорял логи.
            add_log("DEBUG", f"Failed to detect systemd xray config path: {e}")
        with _diag_cache_lock:
            _diag_cache["systemd_cfg"] = (now, value)
        return value

    @staticmethod
    def _systemd_active():
        """Проверяет, активен ли systemd-сервис xray."""
        now = time.monotonic()
        with _diag_cache_lock:
            ts, cached = _diag_cache["active"]
        if ts and now - ts < _SYSTEMD_ACTIVE_TTL:
            return bool(cached)
        active = False
        try:
            r = subprocess.run(
                ["systemctl", "is-active", "xray"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            active = r.stdout.strip() == "active"
        except Exception as e:
            add_log("DEBUG", f"Failed to check systemd active: {e}")
        with _diag_cache_lock:
            _diag_cache["active"] = (now, active)
        return active

    @staticmethod
    def _ss_listen(port):
        """Проверяет, слушает ли процесс указанный TCP-порт (через ss)."""
        now = time.monotonic()
        with _ss_cache_lock:
            cached = _ss_cache.get(port)
        if cached and now - cached[0] < _SS_LISTEN_TTL:
            return cached[1]
        line_value = None
        try:
            r = subprocess.run(
                ["ss", "-lntp"], capture_output=True, text=True, timeout=3
            )
            for line in (r.stdout or "").splitlines():
                if f":{port}" in line:
                    line_value = line.strip()
                    break
        except Exception as e:
            add_log("DEBUG", f"Failed to check port {port}: {e}")
        with _ss_cache_lock:
            _ss_cache[port] = (now, line_value)
        return line_value

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
        """Собирает диагностическую информацию о состоянии Xray.

        Результат кэшируется на несколько секунд: страница настроек опрашивает
        статус каждые 5 с, и без кэша каждый опрос запускал systemctl/ss.
        """
        now = time.monotonic()
        with self._diag_result_lock:
            cached = self._diag_result_cache["data"]
            if cached is not None and now - self._diag_result_cache["ts"] < _DIAG_TTL:
                return dict(cached)
        mgr = str(xray_config_path().resolve())
        systemd_cfg = self._detect_systemd_config()
        inbounds = self._config_inbound_listeners()
        socks_port = Settings.socks_port()
        http_port = Settings.http_port()
        api_port = Settings.api_port()
        has_socks = any(
            ib.get("port") == socks_port and ib.get("protocol") == "socks"
            for ib in inbounds
        )
        result = {
            "manager_config_path": mgr,
            "systemd_config_path": systemd_cfg,
            "config_mismatch": bool(systemd_cfg and systemd_cfg != mgr),
            "systemd_active": self._systemd_active(),
            "config_inbounds": inbounds,
            "socks_in_config": has_socks,
            "ports": {str(p): self._ss_listen(p) for p in (socks_port, http_port, api_port)},
            "proxy_listen": Settings.proxy_listen(),
        }
        with self._diag_result_lock:
            self._diag_result_cache = {"data": dict(result), "ts": now}
        return result


xray_configurator = XrayConfigurator()
