"""API-маршруты: прокси, источники, настройки, Xray, логи, импорт."""

import re
import sqlite3
import subprocess
import threading

from flask import Blueprint, request, jsonify

from ..db import db_q, get_setting, set_setting, xray_bin
from ..utils import add_log, moscow_str, now_utc, SUBSCRIBE_FILE, xray_diagnose
from ..vless import parse_vless
from ..tester import (
    test_proxy,
    update_proxy_status,
    update_vless_status,
    test_and_update,
    test_and_update_vless,
    update_all,
    update_all_vless,
    test_vless_real,
)
from ..importer import import_from_url
from ..xray_config import apply_all_proxies
from ..xray_api import (
    xray_api_ok,
    list_active_outbounds,
    _systemctl_restart_xray,
)

api_bp = Blueprint("api", __name__, url_prefix="/api")


# ─── Логи ───


@api_bp.route("/logs")
def api_logs():
    """GET /api/logs?limit=&offset=&level= — возвращает логи с пагинацией (timestamp в MSK)."""
    limit = request.args.get("limit", type=int, default=50)
    offset = request.args.get("offset", type=int, default=0)
    level = request.args.get("level", "").strip().upper()
    where = ""
    params = []
    if level in ("INFO", "WARN", "ERROR"):
        where = "WHERE level = ?"
        params = [level]
    total = db_q(f"SELECT COUNT(*) c FROM logs {where}", params)[0]["c"]
    rows = db_q(
        f"SELECT id, timestamp, level, message FROM logs {where} ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
    )
    logs = []
    for r in rows:
        d = dict(r)
        if d.get("timestamp"):
            try:
                d["timestamp"] = moscow_str(d["timestamp"])
            except Exception:
                pass
        logs.append(d)
    return jsonify(logs=logs, total=total)


@api_bp.route("/logs/clear", methods=["POST"])
def api_logs_clear():
    """POST /api/logs/clear — очищает все логи."""
    db_q("DELETE FROM logs")
    add_log("INFO", "Logs cleared")
    return jsonify(success=True)


# ─── Прокси ───


def proxy_filter_clause(f):
    """Строит SQL WHERE-условие для фильтрации прокси по статусу."""
    if f == "working":
        return "WHERE status='working'"
    elif f == "vless":
        return "WHERE latency_vless > 0"
    elif f == "failed_recent":
        return "WHERE status='failed' AND (failed_since IS NULL OR failed_since >= datetime('now', '-24 hours'))"
    return ""


@api_bp.route("/proxies")
def api_proxies():
    """GET /api/proxies?filter=&country=&limit=&offset= — список прокси с пагинацией."""
    f = request.args.get("filter", "")
    c = request.args.get("country", "")
    limit = request.args.get("limit", type=int)
    offset = request.args.get("offset", type=int, default=0)
    clause = proxy_filter_clause(f)
    if c == "RU":
        clause = (
            clause + " AND " if clause else "WHERE "
        ) + "status='working' AND country='RU'"
    elif c == "world":
        clause = (
            clause + " AND " if clause else "WHERE "
        ) + "status='working' AND country != '' AND country != 'RU'"

    total = db_q(f"SELECT COUNT(*) as c FROM proxies {clause}")[0]["c"]
    limit_sql = ""
    if limit is not None:
        limit_sql = f" LIMIT {limit} OFFSET {offset}"
    rows = db_q(
        f"SELECT id, host, port, country, status, latency, latency_vless, failed_since, security, link FROM proxies {clause} ORDER BY status, latency{limit_sql}"
    )
    if limit is not None:
        return jsonify(proxies=[dict(r) for r in rows], total=total)
    return jsonify([dict(r) for r in rows])


@api_bp.route("/status")
def api_status():
    """GET /api/status — статистика по прокси (total, working, failed_recent, ru, world)."""
    total = db_q("SELECT COUNT(*) c FROM proxies")[0]["c"]
    working = db_q("SELECT COUNT(*) c FROM proxies WHERE status='working'")[0]["c"]
    failed_recent = db_q(
        "SELECT COUNT(*) c FROM proxies WHERE status='failed' AND (failed_since IS NULL OR failed_since >= datetime('now', '-24 hours'))"
    )[0]["c"]
    working_vless = db_q(
        "SELECT COUNT(*) c FROM proxies WHERE status='working' AND latency_vless > 0"
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
        working_vless=working_vless,
        failed_recent=failed_recent,
        ru=ru,
        world=world,
    )


@api_bp.route("/add", methods=["POST"])
def api_add():
    """POST /api/add — добавляет прокси по vless:// ссылке."""
    link = (request.get_json(silent=True) or {}).get("link", "").strip()
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
                now_utc(),
            ),
        )
        add_log("INFO", f"Added proxy: {parsed['host']}:{parsed['port']}")
        threading.Thread(
            target=lambda: test_and_update_vless(link), daemon=True
        ).start()
        return jsonify(success=True)
    except sqlite3.IntegrityError:
        return jsonify(error="Already exists"), 409


@api_bp.route("/test/<int:pid>", methods=["POST"])
def api_test(pid):
    """POST /api/test/<id> — тестирует один прокси."""
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


@api_bp.route("/delete/<int:pid>", methods=["DELETE"])
def api_delete(pid):
    """DELETE /api/delete/<id> — удаляет прокси."""
    db_q("DELETE FROM proxies WHERE id=?", (pid,))
    add_log("INFO", f"Deleted proxy #{pid}")
    return jsonify(success=True)


@api_bp.route("/test-all", methods=["POST"])
def api_test_all():
    """POST /api/test-all — запускает TCP-тестирование всех прокси в фоне."""
    threading.Thread(target=update_all, daemon=True).start()
    return jsonify(success=True)


@api_bp.route("/test-all-vless", methods=["POST"])
def api_test_all_vless():
    """POST /api/test-all-vless — запускает реальное VLESS-тестирование всех прокси."""
    threading.Thread(target=update_all_vless, daemon=True).start()
    return jsonify(success=True)


@api_bp.route("/cleanup", methods=["POST"])
def api_cleanup():
    """POST /api/cleanup — удаляет все прокси со статусом failed."""
    count = db_q("SELECT COUNT(*) c FROM proxies WHERE status='failed'")[0]["c"]
    db_q("DELETE FROM proxies WHERE status='failed'")
    add_log("INFO", f"Cleaned up {count} failed proxies")
    return jsonify(success=True, deleted=count)


@api_bp.route("/proxies/batch-delete", methods=["POST"])
def api_proxies_batch_delete():
    """POST /api/proxies/batch-delete — удаляет несколько прокси по IDs."""
    ids = (request.get_json(silent=True) or {}).get("ids", [])
    if not ids:
        return jsonify(error="No ids provided"), 400
    placeholders = ",".join("?" * len(ids))
    db_q(f"DELETE FROM proxies WHERE id IN ({placeholders})", ids)
    add_log("INFO", f"Batch deleted {len(ids)} proxies")
    return jsonify(success=True, deleted=len(ids))


@api_bp.route("/proxies/batch-test", methods=["POST"])
def api_proxies_batch_test():
    """POST /api/proxies/batch-test — тестирует несколько прокси по IDs."""
    ids = (request.get_json(silent=True) or {}).get("ids", [])
    if not ids:
        return jsonify(error="No ids provided"), 400
    placeholders = ",".join("?" * len(ids))
    rows = db_q(f"SELECT id, link FROM proxies WHERE id IN ({placeholders})", ids)
    threading.Thread(target=_batch_test, args=(rows,), daemon=True).start()
    return jsonify(success=True, queued=len(rows))


@api_bp.route("/proxies/batch-test-vless", methods=["POST"])
def api_proxies_batch_test_vless():
    """POST /api/proxies/batch-test-vless — тестирует только VLESS прокси
    реальным подключением через Xray (пинг + валидация профиля)."""
    ids = (request.get_json(silent=True) or {}).get("ids", [])
    if not ids:
        return jsonify(error="No ids provided"), 400
    placeholders = ",".join("?" * len(ids))
    rows = db_q(
        f"SELECT id, link FROM proxies WHERE id IN ({placeholders}) AND link LIKE 'vless://%'",
        ids,
    )
    if not rows:
        return jsonify(error="No VLESS proxies found in selection"), 400
    threading.Thread(target=_batch_test_vless, args=(rows,), daemon=True).start()
    return jsonify(success=True, queued=len(rows))


def _batch_test(rows):
    for r in rows:
        ok, lat = test_proxy(r["link"])
        update_proxy_status(r["id"], ok, lat)
    apply_all_proxies()
    add_log("INFO", f"Batch test completed for {len(rows)} proxies")


def _batch_test_vless(rows):
    """Батч-тест VLESS прокси через реальный запуск Xray."""
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
    add_log("INFO", f"VLESS real test completed: {ok_count}/{len(rows)} working")


# ─── Источники ───


@api_bp.route("/sources", methods=["GET"])
def api_sources_list():
    """GET /api/sources — список источников."""
    rows = db_q("SELECT * FROM sources ORDER BY created_at DESC")
    return jsonify([dict(r) for r in rows])


@api_bp.route("/sources", methods=["POST"])
def api_sources_add():
    """POST /api/sources — добавляет источник."""
    body = request.get_json(silent=True) or {}
    name = body.get("name", "").strip()
    url = body.get("url", "").strip()
    if not name or not url:
        return jsonify(error="Name and URL required"), 400
    try:
        db_q(
            "INSERT INTO sources (name, url, created_at) VALUES (?, ?, ?)",
            (name, url, now_utc()),
        )
        add_log("INFO", f"Added source: {name}")
        return jsonify(success=True)
    except sqlite3.IntegrityError:
        return jsonify(error="URL already exists"), 409


@api_bp.route("/sources/<int:sid>", methods=["DELETE"])
def api_sources_delete(sid):
    """DELETE /api/sources/<id> — удаляет источник."""
    db_q("DELETE FROM sources WHERE id=?", (sid,))
    add_log("INFO", f"Deleted source #{sid}")
    return jsonify(success=True)


@api_bp.route("/sources/<int:sid>/import", methods=["POST"])
def api_sources_import_one(sid):
    """POST /api/sources/<id>/import — импортирует из одного источника."""
    rows = db_q("SELECT url FROM sources WHERE id=?", (sid,))
    if not rows:
        return jsonify(error="Not found"), 404
    added = import_from_url(rows[0]["url"])
    db_q("UPDATE sources SET last_import=? WHERE id=?", (now_utc(), sid))
    threading.Thread(target=update_all_vless, daemon=True).start()
    return jsonify(success=True, added=added)


@api_bp.route("/sources/import-all", methods=["POST"])
def api_sources_import_all():
    """POST /api/sources/import-all — импортирует из всех источников."""
    rows = db_q("SELECT id, url FROM sources")
    total = 0
    for r in rows:
        added = import_from_url(r["url"])
        db_q("UPDATE sources SET last_import=? WHERE id=?", (now_utc(), r["id"]))
        total += added
    threading.Thread(target=update_all_vless, daemon=True).start()
    add_log("INFO", f"Imported {total} proxies from all sources")
    return jsonify(success=True, added=total)


# ─── Настройки ───


@api_bp.route("/settings", methods=["GET"])
def api_settings_get():
    """GET /api/settings — все настройки."""
    rows = db_q("SELECT key, value FROM settings ORDER BY key")
    return jsonify({r["key"]: r["value"] for r in rows})


@api_bp.route("/settings", methods=["POST"])
def api_settings_set():
    """POST /api/settings — сохраняет настройки; при изменении allowed_countries пересобирает конфиг."""
    data = request.get_json(silent=True) or {}
    needs_rebuild = "allowed_countries" in data
    for k, v in data.items():
        set_setting(k, str(v))
    add_log("INFO", f"Settings updated: {', '.join(data.keys())}")
    if needs_rebuild:
        threading.Thread(target=apply_all_proxies, daemon=True).start()
    d = xray_diagnose()
    hint = None
    if d["systemd_active"]:
        if d["config_mismatch"]:
            hint = f"Panel config ≠ systemd. Set path to: {d['systemd_config_path']}"
        else:
            hint = "sudo systemctl restart xray"
    return jsonify(success=True, diagnose=d, restart_hint=hint)


# ─── Xray ───


@api_bp.route("/xray/status", methods=["GET"])
def api_xray_status():
    """GET /api/xray/status — статус Xray (running, API, systemd, outbounds)."""
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


@api_bp.route("/xray/outbounds", methods=["GET"])
def api_xray_outbounds():
    """GET /api/xray/outbounds — список outbound с информацией о трафике."""
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


@api_bp.route("/xray/start", methods=["POST"])
def api_xray_start():
    """POST /api/xray/start — запускает Xray через systemctl."""
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


@api_bp.route("/xray/stop", methods=["POST"])
def api_xray_stop():
    """POST /api/xray/stop — останавливает Xray через systemctl."""
    try:
        subprocess.run(["systemctl", "stop", "xray"], capture_output=True, timeout=15)
    except Exception:
        pass
    add_log("INFO", "Xray stopped via systemd")
    return jsonify(success=True)


@api_bp.route("/xray-restart", methods=["POST"])
def api_xray_restart():
    """POST /api/xray-restart — перезапускает Xray через systemctl."""
    ok = _systemctl_restart_xray()
    if ok:
        return jsonify(success=True, message="xray restarted via systemd")
    return jsonify(error="systemctl restart xray failed"), 500


# ─── Подписка / Файлы ───


@api_bp.route("/subscribe.txt")
def api_subscribe():
    """GET /api/subscribe.txt — кешированный subscription file для клиентов."""
    if SUBSCRIBE_FILE.exists():
        return (
            SUBSCRIBE_FILE.read_text(encoding="utf-8"),
            200,
            {
                "Content-Type": "text/plain; charset=utf-8",
            },
        )
    return "// no proxies yet", 200, {"Content-Type": "text/plain; charset=utf-8"}


@api_bp.route("/countries")
def api_countries():
    """GET /api/countries — список стран с количеством прокси и статусом enabled."""
    allowed_raw = get_setting("allowed_countries", "").strip()
    allowed_set = set(c.strip() for c in allowed_raw.split(",") if c.strip())
    rows = db_q(
        "SELECT country, COUNT(*) cnt FROM proxies "
        "WHERE country != '' AND country IS NOT NULL AND length(country)=2 "
        "GROUP BY country ORDER BY country"
    )
    countries = []
    for r in rows:
        cc = r["country"]
        working = db_q(
            "SELECT COUNT(*) c FROM proxies WHERE country=? AND status='working'",
            (cc,),
        )[0]["c"]
        countries.append(
            {
                "code": cc,
                "total": r["cnt"],
                "working": working,
                "enabled": cc in allowed_set if allowed_raw else True,
            }
        )
    return jsonify(countries=countries, allowed=allowed_raw)


# ─── Импорт ───


@api_bp.route("/import", methods=["POST"])
def api_import():
    """POST /api/import — импорт прокси по URL подписки."""
    url = (request.get_json(silent=True) or {}).get("url", "")
    added = import_from_url(url)
    threading.Thread(target=update_all_vless, daemon=True).start()
    return jsonify(success=True, added=added)
