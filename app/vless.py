"""Парсинг VLESS ссылок и построение streamSettings."""

import html
import re
from typing import Optional
from urllib.parse import urlparse, parse_qs, unquote

_VALID_FLOWS: frozenset = frozenset({"xtls-rprx-vision", "xtls-rprx-direct"})
_UUID_RE: re.Pattern = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)

# Транспорты Xray и их псевдонимы из клиентских подписок. `raw` — новое имя
# TCP в части клиентов; `splithttp` — старое имя XHTTP; `gun` — gRPC.
_NETWORK_ALIASES = {
    "raw": "tcp",
    "splithttp": "xhttp",
    "gun": "grpc",
}
_KNOWN_NETWORKS = frozenset(
    {"tcp", "ws", "grpc", "kcp", "h2", "http", "xhttp", "quic", "httpupgrade"}
)
_SECURITY_ALIASES = {
    "": "none",
    "false": "none",
    "0": "none",
    "no": "none",
    "null": "none",
    "xtls": "tls",
}

_NET_RE: re.Pattern = re.compile(r"[a-z][a-z0-9_-]*")


def sanitize_flow(flow: Optional[str]) -> str:
    """Очищает flow от мусора (фрагменты #remark, &param)."""
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


def normalize_network(value: Optional[str]) -> str:
    """Приводит `type` из ссылки к имени транспорта Xray.

    В подписках встречается мусор, приклеенный к транспорту:
    `type=tcp%23%F0%9F…` (ремарка следующей ссылки), `type=raw`,
    `type=httpupgrade`. Берём ведущий токен и раскрываем псевдонимы, иначе
    валидный узел отбрасывался как «unsupported transport».
    """
    if not value:
        return "tcp"
    text = unquote(str(value)).strip().lower()
    m = _NET_RE.match(text)
    if not m:
        return "tcp"
    net = m.group(0)
    return _NETWORK_ALIASES.get(net, net)


def normalize_security(value: Optional[str]) -> str:
    """Приводит `security` к tls/reality/none (false/0/xtls из подписок)."""
    text = unquote(str(value or "")).strip().lower()
    text = _SECURITY_ALIASES.get(text, text)
    if text in ("tls", "reality", "none"):
        return text
    return "none"


def is_known_network(value: Optional[str]) -> bool:
    """Умеет ли stream_settings собрать этот транспорт."""
    return normalize_network(value) in _KNOWN_NETWORKS


def sanitize_short_id(sid: Optional[str]) -> str:
    """Оставляет только hex-часть shortId, обрезая мусор."""
    if not sid:
        return ""
    sid = unquote(str(sid)).split("#")[0].split("&")[0].strip()
    m = re.match(r"^([0-9a-fA-F]{1,16})", sid)
    return m.group(1) if m else ""


def _vless_param(parsed: dict, *keys: str) -> str:
    """Достаёт первое непустое значение из parsed по списку ключей."""
    for k in keys:
        v = parsed.get(k)
        if v:
            return v
    return ""


def _clean_param(value: str) -> str:
    """Снимает мусор, приклеенный к значению параметра подписки."""
    text = unquote(str(value or "")).strip()
    return text.split("#")[0].split("&")[0].strip()


def parse_vless(link: str) -> Optional[dict]:
    """Разбирает vless:// строку в словарь с параметрами.

    Возвращает None, если ссылка невалидна или UUID не проходит проверку.
    Битый порт (`vless://uuid@host:99999`) — тоже невалидная ссылка: urlparse
    бросает на нём ValueError, и без перехвата одна строка в подписке роняла
    импорт целого источника пятисоткой.

    Ссылки из публичных подписок часто содержат HTML-мнемоники (`&amp;`) —
    без `html.unescape` параметры `pbk`/`sid`/`sni` не находились, и валидные
    reality-узлы отбрасывались как «invalid reality publicKey».
    """
    if not link:
        return None
    link = html.unescape(str(link).strip())
    if not link.lower().startswith("vless://"):
        return None
    try:
        parsed = urlparse(link.replace("vless://", "https://", 1))
        uid, server, port = parsed.username, parsed.hostname, parsed.port
    except ValueError:
        return None
    if not uid or not server or port is None:
        return None
    uid = _clean_param(uid)
    if not _UUID_RE.match(uid):
        return None
    result: dict = {
        "uid": uid,
        "server": server,
        "host": server,
        "port": int(port),
        "link": link,
    }
    for k, vals in parse_qs(parsed.query, keep_blank_values=True).items():
        # `amp;pbk` и подобное — следы `&amp;` в старых подписках; после
        # html.unescape их быть не должно, но чистим и ключ.
        key = k[4:] if k.lower().startswith("amp;") else k
        if key in result and key != "host":
            continue
        result[key] = _clean_param(vals[0]) if vals else ""
    # ?host= в VLESS — обычно WS/HTTP Host, не адрес подключения
    if result.get("host") != server:
        result["headerHost"] = result["host"]
    result["host"] = server
    result["server"] = server

    result["type"] = normalize_network(result.get("type"))
    result["security"] = normalize_security(result.get("security"))
    if "flow" in result:
        result["flow"] = sanitize_flow(result["flow"])
    if "sid" in result:
        result["sid"] = sanitize_short_id(result["sid"])
    if "pbk" in result:
        result["pbk"] = _clean_param(result["pbk"])
    elif "publicKey" in result:
        result["publicKey"] = _clean_param(result["publicKey"])
    fragment = unquote(parsed.fragment) if parsed.fragment else ""
    country_m = re.search(r"^([A-Z]{2})\b", fragment) or re.search(
        r"[#\s]([A-Z]{2})\b", fragment
    )
    result["country"] = country_m.group(1) if country_m else ""
    return result


def _sanitize_outbounds(cfg: dict) -> dict:
    """Исправляет пропущенные теги outbound и чистит flow/shortId (Xray 26+)."""
    used_tags: set = set()
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


def _reality_server_name(parsed: dict) -> str:
    """Возвращает sni/serverName для reality/tls."""
    return (
        _vless_param(parsed, "sni", "serverName")
        or parsed.get("headerHost")
        or parsed["server"]
    )


def _truthy(value: Optional[str]) -> bool:
    return (unquote(str(value or "")).strip().lower() in ("1", "true", "yes"))


def stream_settings(parsed: dict) -> dict:
    """Строит streamSettings из распарсенной VLESS ссылки.

    Поддерживает: tcp/raw, ws, grpc, kcp, h2/http, httpupgrade, xhttp
    (включая псевдоним splithttp). Безопасность: tls, reality, none.
    """
    net = normalize_network(parsed.get("type"))
    sec = normalize_security(parsed.get("security"))
    s: dict = {"network": net}
    hdr_host = parsed.get("headerHost") or _vless_param(parsed, "host")
    if net == "ws":
        ws = {}
        if parsed.get("path"):
            ws["path"] = parsed["path"]
        if hdr_host:
            ws["host"] = hdr_host
        if ws:
            s["wsSettings"] = ws
    elif net == "grpc":
        g = {"multiMode": str(parsed.get("mode", "")).lower() == "multi"}
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
    elif net in ("h2", "http"):
        h2 = {}
        if parsed.get("path"):
            h2["path"] = parsed["path"]
        if hdr_host:
            h2["host"] = [hdr_host]
        s["httpSettings"] = h2
    elif net == "httpupgrade":
        hu = {}
        if parsed.get("path"):
            hu["path"] = parsed["path"]
        if hdr_host:
            hu["host"] = hdr_host
        s["httpupgradeSettings"] = hu
    elif net == "xhttp":
        xh = {}
        if parsed.get("path"):
            xh["path"] = parsed["path"]
        if hdr_host:
            xh["host"] = hdr_host
        if parsed.get("mode"):
            xh["mode"] = parsed["mode"]
        if xh:
            s["xhttpSettings"] = xh
    if sec == "tls":
        s["security"] = "tls"
        tls = {"serverName": _reality_server_name(parsed)}
        if parsed.get("alpn"):
            tls["alpn"] = parsed["alpn"].split(",")
        if parsed.get("fp"):
            tls["fingerprint"] = parsed["fp"]
        if _truthy(parsed.get("insecure")) or _truthy(parsed.get("allowInsecure")):
            tls["allowInsecure"] = True
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
