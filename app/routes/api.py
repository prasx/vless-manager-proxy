"""API-маршруты: прокси, источники, настройки, Xray, логи, импорт."""

import re
import sqlite3
import subprocess
import threading
import time

from flask import Blueprint, request, jsonify

from ..db import db_q, Settings
from ..utils import add_log, moscow_str, now_utc
from config import SUBSCRIBE_FILE
from ..vless import parse_vless
from ..proxy_manager import proxy_manager
from ..importer import import_from_url
from ..xray_configurator import xray_configurator
import json as json_module

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
    if level in ("DEBUG", "INFO", "WARN", "ERROR"):
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
        return "WHERE status='working' AND latency_vless > 0"
    elif f == "failed_recent":
        return "WHERE status='failed' AND (failed_since IS NULL OR failed_since >= datetime('now', '-24 hours'))"
    elif f == "top_speed":
        return "WHERE speed_kbps >= 5000"
    return ""


@api_bp.route("/proxies")
def api_proxies():
    """GET /api/proxies?filter=&source=&limit=&offset= — список прокси с пагинацией."""
    f = request.args.get("filter", "")
    src = request.args.get("source", "")
    limit = request.args.get("limit", type=int)
    offset = request.args.get("offset", type=int, default=0)
    clause = proxy_filter_clause(f)
    if src == "unknown":
        clause = (clause + " AND " if clause else "WHERE ") + "source_id IS NULL"
    elif src and src.isdigit():
        clause = (clause + " AND " if clause else "WHERE ") + f"source_id = {int(src)}"

    total = db_q(f"SELECT COUNT(*) as c FROM proxies {clause}")[0]["c"]
    limit_sql = ""
    if limit is not None:
        limit_sql = f" LIMIT {limit} OFFSET {offset}"
    order = "speed_kbps DESC" if f == "top_speed" else "status, latency"
    rows = db_q(
        f"SELECT id, host, port, country, status, latency, latency_vless, speed_kbps, failed_since, security, link FROM proxies {clause} ORDER BY {order}{limit_sql}"
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
    top_speed = db_q("SELECT COUNT(*) c FROM proxies WHERE speed_kbps >= 5000")[0]["c"]
    ru = db_q("SELECT COUNT(*) c FROM proxies WHERE status='working' AND country='RU'")[
        0
    ]["c"]
    world = db_q(
        "SELECT COUNT(*) c FROM proxies WHERE status='working' AND country != '' AND country != 'RU'"
    )[0]["c"]
    sources = db_q(
        "SELECT s.id, s.name, COUNT(p.id) cnt FROM sources s LEFT JOIN proxies p ON p.source_id = s.id GROUP BY s.id HAVING cnt > 0 ORDER BY s.name"
    )
    unknown = db_q("SELECT COUNT(*) c FROM proxies WHERE source_id IS NULL")[0]["c"]
    return jsonify(
        total=total,
        working=working,
        failed_recent=failed_recent,
        top_speed=top_speed,
        ru=ru,
        world=world,
        sources=[dict(r) for r in sources],
        unknown_count=unknown,
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
        if not parsed.get("country"):
            from ..utils import enrich_all_unknown_countries

            threading.Thread(target=enrich_all_unknown_countries, daemon=True).start()
        threading.Thread(
            target=lambda: proxy_manager.test_and_update_vless(link), daemon=True
        ).start()
        return jsonify(success=True)
    except sqlite3.IntegrityError:
        return jsonify(error="Already exists"), 409


@api_bp.route("/test/<int:pid>", methods=["POST"])
def api_test(pid):
    """POST /api/test/<id> — тестирует один прокси (VLESS)."""
    rows = db_q("SELECT link FROM proxies WHERE id=?", (pid,))
    if not rows:
        return jsonify(error="Not found"), 404
    ok, lat = proxy_manager.test_vless_real(rows[0]["link"])
    proxy_manager._update_vless_status(pid, ok, lat if ok else 0)
    status = "working" if ok else "failed"
    add_log("INFO", f"Tested proxy #{pid} → {status} ({lat}ms)")
    return jsonify(status=status, latency=lat)


@api_bp.route("/delete/<int:pid>", methods=["DELETE"])
def api_delete(pid):
    """DELETE /api/delete/<id> — удаляет прокси."""
    db_q("DELETE FROM proxies WHERE id=?", (pid,))
    add_log("INFO", f"Deleted proxy #{pid}")
    return jsonify(success=True)


@api_bp.route("/test-all", methods=["POST"])
def api_test_all():
    """POST /api/test-all — запускает VLESS-тестирование всех прокси в фоне."""
    threading.Thread(target=proxy_manager.test_all_vless, daemon=True).start()
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
    """POST /api/proxies/batch-test — тестирует несколько прокси по IDs (VLESS)."""
    ids = (request.get_json(silent=True) or {}).get("ids", [])
    if not ids:
        return jsonify(error="No ids provided"), 400
    placeholders = ",".join("?" * len(ids))
    rows = db_q(f"SELECT id, link FROM proxies WHERE id IN ({placeholders})", ids)
    threading.Thread(
        target=proxy_manager.batch_test_vless, args=(rows,), daemon=True
    ).start()
    return jsonify(success=True, queued=len(rows))


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
    added = import_from_url(rows[0]["url"], source_id=sid)
    db_q("UPDATE sources SET last_import=? WHERE id=?", (now_utc(), sid))
    threading.Thread(target=proxy_manager.test_all_vless, daemon=True).start()
    return jsonify(success=True, added=added)


@api_bp.route("/sources/import-all", methods=["POST"])
def api_sources_import_all():
    """POST /api/sources/import-all — импортирует из всех источников."""
    rows = db_q("SELECT id, url FROM sources")
    total = 0
    for r in rows:
        added = import_from_url(r["url"], source_id=r["id"])
        db_q("UPDATE sources SET last_import=? WHERE id=?", (now_utc(), r["id"]))
        total += added
    threading.Thread(target=proxy_manager.test_all_vless, daemon=True).start()
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
    rebuild_keys = {"allowed_countries", "geo_enabled", "max_active_proxies", "probe_url", "observatory_probe_interval"}
    needs_rebuild = bool(rebuild_keys & set(data.keys()))
    for k, v in data.items():
        Settings.set(k, str(v))
    add_log("INFO", f"Settings updated: {', '.join(data.keys())}")
    if needs_rebuild:
        threading.Thread(target=xray_configurator.apply_all, daemon=True).start()
    d = xray_configurator.diagnose()
    hint = None
    if d["systemd_active"]:
        if d["config_mismatch"]:
            hint = f"Panel config ≠ systemd. Set path to: {d['systemd_config_path']}"
        else:
            hint = "sudo systemctl restart xray"
    return jsonify(success=True, diagnose=d, restart_hint=hint)


# ─── Бекап настроек и источников ───


@api_bp.route("/backup")
def api_backup_export():
    """GET /api/backup — экспорт всех настроек и источников в JSON."""
    settings = {
        r["key"]: r["value"]
        for r in db_q("SELECT key, value FROM settings ORDER BY key")
    }
    sources = [
        dict(r)
        for r in db_q(
            "SELECT id, name, url, last_import, created_at FROM sources ORDER BY created_at"
        )
    ]
    return jsonify(
        version=2,
        exported_at=moscow_str(),
        settings=settings,
        sources=sources,
    )


@api_bp.route("/backup/import", methods=["POST"])
def api_backup_import():
    """POST /api/backup/import — импорт настроек и источников из JSON."""
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict) or "settings" not in data or "sources" not in data:
        return jsonify(error="Invalid backup format: need settings + sources"), 400

    imported = {"settings": 0, "sources": 0}

    for k, v in data["settings"].items():
        cur = Settings.get(k)
        val = str(v)
        # Не затираем настроенные geosite-правила пустым массивом из старого бекапа
        if k == "geosite_rules" and val == "[]" and cur and cur != "[]":
            add_log("DEBUG", f"Backup: skipped empty geosite_rules (preserving {len(json_module.loads(cur))} existing rules)")
            continue
        Settings.set(k, val)
        imported["settings"] += 1

    for src in data["sources"]:
        name = (src.get("name") or "").strip()
        url = (src.get("url") or "").strip()
        if not name or not url:
            continue
        try:
            last_import = src.get("last_import") or None
            created_at = src.get("created_at") or now_utc()
            db_q(
                "INSERT OR IGNORE INTO sources (name, url, last_import, created_at) VALUES (?, ?, ?, ?)",
                (name, url, last_import, created_at),
            )
            imported["sources"] += 1
        except Exception:
            pass

    add_log(
        "INFO",
        f"Backup imported: {imported['settings']} settings, {imported['sources']} sources (v{data.get('version', 1)})",
    )
    return jsonify(success=True, imported=imported)


# ─── Xray ───


@api_bp.route("/xray/status", methods=["GET"])
def api_xray_status():
    """GET /api/xray/status — статус Xray (running, API, systemd, outbounds)."""
    api_ok = xray_configurator.api_ok()
    d = xray_configurator.diagnose()
    running = api_ok or (d["systemd_active"] and d["ports"].get("1080"))
    active = xray_configurator.list_active_outbounds() if api_ok else []
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
    tags = xray_configurator.list_active_outbounds()
    nodes = [t for t in tags if t.startswith("node")]
    traffic = {}
    try:
        r = subprocess.run(
            [Settings.xray_bin(), "api", "statsquery", "-s", "127.0.0.1:10085"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in r.stdout.splitlines():
            m = re.search(r"outbound>>>([^>]+)>>>traffic>>>([a-z]+)", line)
            if m:
                tag, direction = m.group(1), m.group(2)
                traffic.setdefault(tag, {})[direction] = True
    except Exception as e:
        add_log("WARN", f"Xray statsquery failed: {e}")
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
    except Exception as e:
        add_log("ERROR", f"Xray stop failed: {e}")
    add_log("INFO", "Xray stopped via systemd")
    return jsonify(success=True)


@api_bp.route("/xray-restart", methods=["POST"])
def api_xray_restart():
    """POST /api/xray-restart — перезапускает Xray через systemctl."""
    ok = xray_configurator.restart_via_systemd()
    if ok:
        return jsonify(success=True, message="xray restarted via systemd")
    return jsonify(error="systemctl restart xray failed"), 500


# ─── Подписка / Файлы ───


_last_sub_refresh = 0.0

@api_bp.route("/subscribe.txt")
def api_subscribe():
    """GET /api/subscribe.txt — кешированный subscription file для клиентов.
    Пересобирает не чаще раза в 60 секунд.
    """
    global _last_sub_refresh
    now = time.time()
    if now - _last_sub_refresh > 60:
        _last_sub_refresh = now
        xray_configurator._update_subscribe_cache()
    if SUBSCRIBE_FILE.exists():
        return (
            SUBSCRIBE_FILE.read_text(encoding="utf-8"),
            200,
            {"Content-Type": "text/plain; charset=utf-8"},
        )
    return "// no proxies yet", 200, {"Content-Type": "text/plain; charset=utf-8"}


@api_bp.route("/countries")
def api_countries():
    """GET /api/countries — список стран с количеством прокси и статусом enabled."""
    allowed_raw = Settings.get("allowed_countries", "").strip()
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


# ─── Прогресс тестов ───


@api_bp.route("/test-progress")
def api_test_progress():
    """GET /api/test-progress — текущий статус фонового VLESS-теста."""
    p = proxy_manager.progress
    return jsonify(
        running=p["running"],
        total=p["total"],
        done=p["done"],
        ok=p["ok"],
        label=p["label"],
        last_completed=p["last_completed"],
        last_label=p["last_label"],
        last_ok=p["last_ok"],
        last_total=p["last_total"],
    )


# ─── GeoSite Rules ───


@api_bp.route("/geosite-rules", methods=["GET"])
def api_geosite_rules_get():
    """GET /api/geosite-rules — возвращает список geosite-правил."""
    return jsonify(rules=Settings.geosite_rules())


@api_bp.route("/geosite-rules", methods=["POST"])
def api_geosite_rules_set():
    """POST /api/geosite-rules — сохраняет список geosite-правил."""
    data = request.get_json(silent=True) or {}
    rules = data.get("rules", [])
    for r in rules:
        if not r.get("domain") or not r.get("outboundTag"):
            return jsonify(error="Each rule needs 'domain' and 'outboundTag'"), 400
    Settings.set("geosite_rules", json_module.dumps(rules))
    add_log("INFO", f"GeoSite rules updated: {len(rules)} rules")
    threading.Thread(target=xray_configurator.apply_all, daemon=True).start()
    return jsonify(success=True, count=len(rules))


# ─── Импорт ───


@api_bp.route("/import", methods=["POST"])
def api_import():
    """POST /api/import — импорт прокси по URL подписки."""
    url = (request.get_json(silent=True) or {}).get("url", "")
    added = import_from_url(url)
    threading.Thread(target=proxy_manager.test_all_vless, daemon=True).start()
    return jsonify(success=True, added=added)
