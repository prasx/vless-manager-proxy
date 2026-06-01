"""Парсинг VLESS ссылок и построение streamSettings."""

import re
from urllib.parse import urlparse, parse_qs, unquote

_VALID_FLOWS = frozenset({"xtls-rprx-vision", "xtls-rprx-direct"})
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)


def sanitize_flow(flow):
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


def sanitize_short_id(sid):
    """Оставляет только hex-часть shortId, обрезая мусор."""
    if not sid:
        return ""
    sid = unquote(str(sid)).split("#")[0].split("&")[0].strip()
    m = re.match(r"^([0-9a-fA-F]{1,16})", sid)
    return m.group(1) if m else ""


def _vless_param(parsed, *keys):
    """Достаёт первое непустое значение из parsed по списку ключей."""
    for k in keys:
        v = parsed.get(k)
        if v:
            return v
    return ""


def parse_vless(link):
    """Разбирает vless:// строку в словарь с параметрами.

    Возвращает None, если ссылка невалидна или UUID не проходит проверку.
    """
    link = link.strip()
    if not link.lower().startswith("vless://"):
        return None
    parsed = urlparse(link.replace("vless://", "https://", 1))
    uid, server, port = parsed.username, parsed.hostname, parsed.port
    if not uid or not server or port is None:
        return None
    uid = unquote(str(uid)).split("#")[0].split("&")[0].strip()
    if not _UUID_RE.match(uid):
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
    # ?host= в VLESS — обычно WS/HTTP Host, не адрес подключения
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


def _sanitize_outbounds(cfg):
    """Исправляет пропущенные теги outbound и чистит flow/shortId (Xray 26+)."""
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


def _reality_server_name(parsed):
    """Возвращает sni/serverName для reality/tls."""
    return (
        _vless_param(parsed, "sni", "serverName")
        or parsed.get("headerHost")
        or parsed["server"]
    )


def stream_settings(parsed):
    """Строит streamSettings из распарсенной VLESS ссылки.

    Поддерживает: tcp, ws, grpc, kcp, h2/http, xhttp.
    Безопасность: tls, reality, none.
    """
    net = parsed.get("type", "tcp")
    sec = parsed.get("security", "none")
    s = {"network": net}
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
    elif net == "xhttp":
        xh = {}
        if parsed.get("path"):
            xh["path"] = parsed["path"]
        if hdr_host:
            xh["host"] = hdr_host
        if xh:
            s["xhttpSettings"] = xh
    if sec == "tls":
        s["security"] = "tls"
        tls = {"serverName": _reality_server_name(parsed)}
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
