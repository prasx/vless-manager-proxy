"""API-маршруты: прокси, источники, настройки, Xray, логи, импорт."""

import json
import re
import sqlite3
import subprocess
import threading
import time

from flask import Blueprint, request, jsonify, Response

from ..db import db_q, Settings
from ..utils import add_log, moscow_str, now_utc, count_active_connections, list_active_connections, close_connection, flush_all_connections
from config import SUBSCRIBE_FILE, SOCKS_PORT, HTTP_PORT
from ..vless import parse_vless
from ..proxy_manager import proxy_manager
from ..importer import import_from_url, import_from_txt
from ..xray_configurator import xray_configurator
from ..subscribe import update_subscribe_cache

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
        f"SELECT id, timestamp, level, message, correlation_id FROM logs {where} ORDER BY id DESC LIMIT ? OFFSET ?",
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
        try:
            parsed = json.loads(d["message"])
            if isinstance(parsed, dict) and "msg" in parsed:
                d["message"] = parsed["msg"]
                d["_json"] = parsed
        except (json.JSONDecodeError, TypeError, KeyError):
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
        return "status='working'"
    elif f == "failed_recent":
        return "status='failed' AND (failed_since IS NULL OR failed_since >= datetime('now', '-24 hours'))"
    elif f == "top_speed":
        min_kbps = Settings.min_speed_kbps()
        if min_kbps > 0:
            return f"speed_kbps >= {min_kbps}"
        return "speed_kbps >= 5000"
    return ""


def _blocked_countries_clause() -> tuple[str, list]:
    """SQL-условие для исключения заблокированных стран."""
    blocked = Settings.blocked_countries()
    codes = [c.strip() for c in blocked.split(",") if c.strip()] if blocked else []
    if codes:
        placeholders = ",".join("?" * len(codes))
        return f"country NOT IN ({placeholders})", codes
    return "", []


def _build_where(f, src, search) -> tuple[str, list]:
    clauses = []
    params = []
    fc = proxy_filter_clause(f)
    if fc:
        clauses.append(fc)
    bc_clause, bc_params = _blocked_countries_clause()
    if bc_clause:
        clauses.append(bc_clause)
        params.extend(bc_params)
    if src == "unknown":
        clauses.append("source_id IS NULL")
    elif src and src.isdigit():
        clauses.append("source_id = ?")
        params.append(int(src))
    if search:
        clauses.append("(host LIKE ? OR CAST(id AS TEXT) LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like])
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    return where, params


@api_bp.route("/proxies")
def api_proxies():
    """GET /api/proxies?filter=&source=&search=&limit=&offset= — список прокси с пагинацией."""
    f = request.args.get("filter", "")
    src = request.args.get("source", "")
    search = request.args.get("search", "").strip()
    limit = request.args.get("limit", type=int)
    offset = request.args.get("offset", type=int, default=0)
    where, params = _build_where(f, src, search)

    total = db_q(f"SELECT COUNT(*) as c FROM proxies {where}", params)[0]["c"]
    limit_sql = ""
    limit_params = []
    if limit is not None:
        limit_sql = " LIMIT ? OFFSET ?"
        limit_params = [limit, offset]
    order = "speed_kbps DESC" if f == "top_speed" else "status, latency"
    rows = db_q(
        f"SELECT id, host, port, country, status, latency, latency_vless, speed_kbps, failed_since, security, link FROM proxies {where} ORDER BY {order}{limit_sql}",
        params + limit_params,
    )
    if limit is not None:
        return jsonify(proxies=[dict(r) for r in rows], total=total)
    return jsonify([dict(r) for r in rows])


@api_bp.route("/status")
def api_status():
    """GET /api/status — статистика по прокси (total, working, failed_recent, ru, world)."""
    min_kbps = Settings.min_speed_kbps()
    top_threshold = min_kbps if min_kbps > 0 else 5000
    bc_clause, bc_params = _blocked_countries_clause()
    bc_where = f"WHERE {bc_clause}" if bc_clause else ""
    row = db_q(
        f"""SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status='working' THEN 1 ELSE 0 END) as working,
            SUM(CASE WHEN status='failed' AND (failed_since IS NULL OR failed_since >= datetime('now', '-24 hours')) THEN 1 ELSE 0 END) as failed_recent,
            SUM(CASE WHEN speed_kbps >= {top_threshold} THEN 1 ELSE 0 END) as top_speed,
            SUM(CASE WHEN status='working' AND country='RU' THEN 1 ELSE 0 END) as ru,
            SUM(CASE WHEN status='working' AND country != '' AND country != 'RU' THEN 1 ELSE 0 END) as world,
            SUM(CASE WHEN source_id IS NULL THEN 1 ELSE 0 END) as unknown_count
        FROM proxies {bc_where}""",
        bc_params if bc_clause else [],
    )[0]
    sources = db_q(
        "SELECT s.id, s.name, COUNT(p.id) cnt FROM sources s LEFT JOIN proxies p ON p.source_id = s.id GROUP BY s.id HAVING cnt > 0 ORDER BY s.name"
    )
    return jsonify(
        total=row["total"],
        working=row["working"],
        failed_recent=row["failed_recent"],
        top_speed=row["top_speed"],
        top_speed_threshold=top_threshold,
        ru=row["ru"],
        world=row["world"],
        sources=[dict(r) for r in sources],
        unknown_count=row["unknown_count"],
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
    """POST /api/test/<id> — тестирует один прокси (VLESS + скорость)."""
    rows = db_q("SELECT link FROM proxies WHERE id=?", (pid,))
    if not rows:
        return jsonify(error="Not found"), 404
    ok, lat = proxy_manager.test_vless_real(rows[0]["link"])
    proxy_manager._update_vless_status(pid, ok, lat if ok else 0)
    speed = 0
    if ok:
        speed = proxy_manager._test_speed_single(rows[0]["link"])
        if speed:
            db_q("UPDATE proxies SET speed_kbps=? WHERE id=?", (speed, pid))
    status = "working" if ok else "failed"
    add_log("INFO", f"Tested proxy #{pid} → {status} ({lat}ms, {speed}kbps)")
    return jsonify(status=status, latency=lat, speed=speed)


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
    rows = db_q("SELECT id, name, url, type, last_import, created_at FROM sources ORDER BY created_at DESC")
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


@api_bp.route("/sources/txt", methods=["POST"])
def api_sources_txt_add():
    """POST /api/sources/txt — добавляет TXT-источник."""
    body = request.get_json(silent=True) or {}
    name = body.get("name", "").strip()
    content = body.get("content", "").strip()
    if not name or not content:
        return jsonify(error="Name and content required"), 400
    fake_url = f"txt://{name}"
    try:
        db_q(
            "INSERT INTO sources (name, url, type, content, created_at) VALUES (?, ?, 'txt', ?, ?)",
            (name, fake_url, content, now_utc()),
        )
        add_log("INFO", f"Added TXT source: {name}")
        return jsonify(success=True)
    except sqlite3.IntegrityError:
        return jsonify(error="Source with this name already exists"), 409


@api_bp.route("/sources/<int:sid>/content", methods=["GET"])
def api_sources_content_get(sid):
    """GET /api/sources/<id>/content — возвращает TXT-контент источника."""
    rows = db_q("SELECT type, content, name FROM sources WHERE id=?", (sid,))
    if not rows:
        return jsonify(error="Not found"), 404
    return jsonify(type=rows[0]["type"], content=rows[0]["content"] or "", name=rows[0]["name"])


@api_bp.route("/sources/<int:sid>/content", methods=["PUT"])
def api_sources_content_update(sid):
    """PUT /api/sources/<id>/content — обновляет TXT-контент источника."""
    body = request.get_json(silent=True) or {}
    content = body.get("content", "").strip()
    if not content:
        return jsonify(error="Content required"), 400
    db_q("UPDATE sources SET content=? WHERE id=? AND type='txt'", (content, sid))
    add_log("INFO", f"Updated content for TXT source #{sid}")
    return jsonify(success=True)


@api_bp.route("/sources/<int:sid>/import", methods=["POST"])
def api_sources_import_one(sid):
    """POST /api/sources/<id>/import — импортирует из одного источника."""
    rows = db_q("SELECT url, type FROM sources WHERE id=?", (sid,))
    if not rows:
        return jsonify(error="Not found"), 404
    try:
        if rows[0]["type"] == "txt":
            added = import_from_txt(sid)
        else:
            added = import_from_url(rows[0]["url"], source_id=sid)
    except RuntimeError as e:
        add_log("ERROR", f"Import source #{sid} failed: {e}")
        return jsonify(error=str(e)), 502
    db_q("UPDATE sources SET last_import=? WHERE id=?", (now_utc(), sid))
    test_started = proxy_manager.test_all_vless()
    return jsonify(success=True, added=added, test_queued=test_started)


@api_bp.route("/sources/import-all", methods=["POST"])
def api_sources_import_all():
    """POST /api/sources/import-all — импортирует из всех источников."""
    rows = db_q("SELECT id, url, type FROM sources")
    total = 0
    errors = []
    for r in rows:
        try:
            if r["type"] == "txt":
                added = import_from_txt(r["id"])
            else:
                added = import_from_url(r["url"], source_id=r["id"])
            db_q("UPDATE sources SET last_import=? WHERE id=?", (now_utc(), r["id"]))
            total += added
        except RuntimeError as e:
            errors.append(f"#{r['id']}: {e}")
            add_log("ERROR", f"Import source #{r['id']} failed: {e}")
    test_started = proxy_manager.test_all_vless()
    if errors:
        add_log("WARN", f"Import completed with errors: {'; '.join(errors)}")
    add_log("INFO", f"Imported {total} proxies from all sources")
    return jsonify(success=True, added=total, errors=errors, test_queued=test_started)


# ─── Настройки ───

_REBUILD_KEYS = {
    "blocked_countries", "geo_enabled", "max_active_proxies", "probe_url",
    "observatory_probe_interval", "balancer_strategy", "handshake_timeout", "conn_idle",
    "min_speed_mbps", "sniffing_enabled", "sniffing_dest_override", "sniffing_route_only",
    "geosite_rules",
}


@api_bp.route("/settings", methods=["GET"])
def api_settings_get():
    """GET /api/settings — все настройки."""
    rows = db_q("SELECT key, value FROM settings ORDER BY key")
    return jsonify({r["key"]: r["value"] for r in rows})


@api_bp.route("/settings", methods=["POST"])
def api_settings_set():
    """POST /api/settings — сохраняет настройки."""
    data = request.get_json(silent=True) or {}

    try:
        _validate_settings(data)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    for k, v in data.items():
        Settings.set(k, str(v))
    add_log("INFO", f"Settings updated: {', '.join(data.keys())}")

    if _REBUILD_KEYS & set(data.keys()):
        update_subscribe_cache()
        threading.Thread(target=lambda: xray_configurator.apply_all(blocking=True), daemon=True).start()

    d = xray_configurator.diagnose()
    hint = None
    if d["systemd_active"]:
        if d["config_mismatch"]:
            hint = f"Panel config ≠ systemd. Set path to: {d['systemd_config_path']}"
        else:
            hint = "sudo systemctl restart xray"
    return jsonify(success=True, restart_hint=hint)


_INT_KEYS = {
    "max_active_proxies", "vless_per_proxy_timeout", "log_trim_every", "log_keep",
    "speed_test_max", "handshake_timeout", "conn_idle", "check_interval_db", "check_interval_import",
    "speed_test_adaptive_sec", "max_workers", "probe_timeout", "xray_startup_retries",
}


def _validate_settings(data: dict) -> None:
    """Базовая валидация настроек перед сохранением."""
    for k in _INT_KEYS:
        if k in data:
            try:
                val = int(data[k])
                if val < 0:
                    raise ValueError
            except (ValueError, TypeError):
                raise ValueError(f"{k} must be a positive integer, got {data[k]!r}")


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
            "SELECT id, name, url, type, content, last_import, created_at FROM sources ORDER BY created_at"
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
            add_log(
                "DEBUG",
                f"Backup: skipped empty geosite_rules (preserving {len(json.loads(cur))} existing rules)",
            )
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
            typ = src.get("type", "url")
            content = src.get("content") or None
            db_q(
                "INSERT OR IGNORE INTO sources (name, url, type, content, last_import, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (name, url, typ, content, last_import, created_at),
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
    """GET /api/xray/status — статус Xray (running, API, systemd, outbounds, config)."""
    api_ok = xray_configurator.api_ok()
    d = xray_configurator.diagnose()
    running = api_ok or (d["systemd_active"] and d["ports"].get("1080"))
    active = xray_configurator.list_active_outbounds() if api_ok else []
    nodes = [t for t in active if t.startswith("node")]
    blocked = Settings.blocked_countries()
    codes = [c.strip() for c in blocked.split(",") if c.strip()] if blocked else []
    country_sql = f"AND country NOT IN ({','.join(['?']*len(codes))})" if codes else ""
    min_kbps = Settings.min_speed_kbps()
    speed_sql = f"AND speed_kbps >= {min_kbps}" if min_kbps > 0 else ""
    candidate = db_q(
        f"SELECT COUNT(*) c FROM proxies WHERE status='working' AND latency_vless > 0 {country_sql} {speed_sql}",
        codes,
    )[0]["c"]
    return jsonify(
        running=bool(running),
        api_accessible=api_ok,
        api_endpoint="127.0.0.1:10085",
        systemd_active=d["systemd_active"],
        config_mismatch=d["config_mismatch"],
        active_outbounds=active,
        nodes_in_config=len(nodes),
        config_candidates=candidate,
    )


@api_bp.route("/xray/outbounds", methods=["GET"])
def api_xray_outbounds():
    """GET /api/xray/outbounds — список outbound с информацией о трафике."""
    rc, stdout = xray_configurator._cached_statsquery()
    tags = xray_configurator.list_active_outbounds()
    nodes = [t for t in tags if t.startswith("node")]
    traffic = {}
    if rc == 0:
        for line in stdout.splitlines():
            m = re.search(r"outbound>>>([^>]+)>>>traffic>>>([a-z]+)", line)
            if m:
                tag, direction = m.group(1), m.group(2)
                traffic.setdefault(tag, {})[direction] = True
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


@api_bp.route("/xray/rebuild", methods=["POST"])
def api_xray_rebuild():
    """POST /api/xray/rebuild — пересобрать конфиг и применить (без перезапуска Xray)."""
    threading.Thread(target=lambda: xray_configurator.apply_all(blocking=True), daemon=True).start()
    return jsonify(success=True, message="Config rebuild started")


@api_bp.route("/xray-restart", methods=["POST"])
def api_xray_restart():
    """POST /api/xray-restart — перезапускает Xray через systemctl."""
    ok = xray_configurator.restart_via_systemd()
    if ok:
        return jsonify(success=True, message="xray restarted via systemd")
    return jsonify(error="systemctl restart xray failed"), 500


@api_bp.route("/health")
def api_health():
    """GET /api/health — health check для systemd/monitoring."""
    db_ok = True
    try:
        db_q("SELECT 1")
    except Exception:
        db_ok = False
    xr = xray_configurator
    api_ok = xr.api_ok()
    d = xr.diagnose()
    xray_running = bool(api_ok or (d["systemd_active"] and d["ports"].get("1080")))
    proxy_count = db_q("SELECT COUNT(*) c FROM proxies")[0]["c"]
    return jsonify(
        status="ok" if db_ok else "error",
        db=db_ok,
        xray=dict(
            running=xray_running,
            api_accessible=api_ok,
            systemd_active=d["systemd_active"],
            config_mismatch=d["config_mismatch"],
        ),
        proxies=dict(total=proxy_count),
    )


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
        update_subscribe_cache()
    if SUBSCRIBE_FILE.exists():
        return (
            SUBSCRIBE_FILE.read_text(encoding="utf-8"),
            200,
            {"Content-Type": "text/plain; charset=utf-8"},
        )
    return "// no proxies yet", 200, {"Content-Type": "text/plain; charset=utf-8"}


@api_bp.route("/countries")
def api_countries():
    """GET /api/countries — список стран с количеством прокси, верификацией и статусом blocked."""
    blocked_raw = Settings.get("blocked_countries", "").strip()
    blocked_set = set(c.strip() for c in blocked_raw.split(",") if c.strip())
    rows = db_q(
        """SELECT p.country, COUNT(*) cnt,
           SUM(CASE WHEN p.status='working' THEN 1 ELSE 0 END) as working,
           SUM(CASE WHEN p.country_verified=1 THEN 1 ELSE 0 END) as verified
        FROM proxies p
        WHERE p.country != '' AND p.country IS NOT NULL AND length(p.country)=2
        GROUP BY p.country ORDER BY cnt DESC, working DESC"""
    )
    countries = []
    for r in rows:
        countries.append(
            {
                "code": r["country"],
                "total": r["cnt"],
                "working": r["working"],
                "verified": r["verified"],
                "blocked": r["country"] in blocked_set if blocked_raw else False,
            }
        )
    last_verify = db_q(
        "SELECT MAX(added_at) FROM proxies WHERE country_verified=1"
    )[0][0]
    return jsonify(countries=countries, blocked=blocked_raw, last_verify=last_verify)


# ─── Прогресс тестов ───


@api_bp.route("/test-cancel", methods=["POST"])
def api_test_cancel():
    """POST /api/test-cancel — отменяет текущий фоновый тест."""
    proxy_manager._cancel.set()
    return jsonify(success=True)


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
        started_at=p["started_at"],
    )


@api_bp.route("/test-progress/stream")
def api_test_progress_stream():
    """SSE: поток обновлений test-progress. Альтернатива polling."""
    def generate():
        last_done = -1
        while True:
            p = proxy_manager.progress
            d = dict(
                running=p["running"],
                total=p["total"],
                done=p["done"],
                ok=p["ok"],
                label=p["label"],
                last_completed=p["last_completed"],
                last_label=p["last_label"],
                last_ok=p["last_ok"],
                last_total=p["last_total"],
                started_at=p["started_at"],
            )
            if d["done"] != last_done or not d["running"]:
                yield f"data: {json.dumps(d)}\n\n"
                last_done = d["done"]
                if not d["running"] and d["done"] == d["total"]:
                    return
            time.sleep(0.5)
    return Response(generate(), mimetype="text/event-stream")


# ─── GeoSite Rules ───


@api_bp.route("/performance/recommendations")
def api_performance_recommendations():
    """GET /api/performance/recommendations — рекомендации по настройкам производительности."""
    total = db_q("SELECT COUNT(*) c FROM proxies")[0]["c"]
    working = db_q("SELECT COUNT(*) c FROM proxies WHERE status='working'")[0]["c"]
    speed_enabled = Settings.get("speed_test_enabled", "true") == "true"
    speed_max = int(Settings.get("speed_test_max", "30"))
    workers = Settings.max_workers()
    probe_t = Settings.probe_timeout()
    startup_r = Settings.xray_startup_retries()
    vless_t = Settings.vless_per_proxy_timeout()

    startup_time = startup_r * 0.05
    per_proxy = startup_time + probe_t
    if speed_enabled and working > 0:
        speed_proxies = min(speed_max, working)
        per_proxy += (vless_t + 5) * (speed_proxies / max(1, total))

    batches = max(1, total // workers + (1 if total % workers else 0))
    est_current = batches * per_proxy

    targets = []
    for w, pt in [(10, 5), (10, 4), (8, 5), (8, 4), (5, 5), (5, 4)]:
        b = max(1, total // w + (1 if total % w else 0))
        est = b * (startup_time + pt)
        if speed_enabled and working > 0:
            speed_proxies = min(speed_max, working)
            est += (vless_t + 5) * (speed_proxies / max(1, total))
        targets.append({
            "workers": w,
            "probe_timeout": pt,
            "estimated_seconds": round(est),
            "estimated_label": f"~{est/60:.1f} min",
        })

    return jsonify(
        total=total,
        working=working,
        current={"workers": workers, "probe_timeout": probe_t, "xray_startup_retries": startup_r, "vless_per_proxy_timeout": vless_t, "estimated_seconds": round(est_current), "estimated_label": f"~{est_current/60:.1f} min"},
        targets=targets,
    )


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
    Settings.set("geosite_rules", json.dumps(rules))
    add_log("INFO", f"GeoSite rules updated: {len(rules)} rules")
    update_subscribe_cache()
    threading.Thread(target=lambda: xray_configurator.apply_all(blocking=True), daemon=True).start()
    return jsonify(success=True, count=len(rules))


# ─── Импорт ───


@api_bp.route("/import", methods=["POST"])
def api_import():
    """POST /api/import — импорт прокси по URL подписки."""
    url = (request.get_json(silent=True) or {}).get("url", "")
    added = import_from_url(url)
    threading.Thread(target=proxy_manager.test_all_vless, daemon=True).start()
    return jsonify(success=True, added=added)


# ─── Traffic history ───


@api_bp.route("/traffic/current")
def api_traffic_current():
    """GET /api/traffic/current — трафик (nftables real-time + DB history) + активные соединения."""
    from ..proxy_manager import proxy_manager

    conns = count_active_connections([SOCKS_PORT, HTTP_PORT])
    total_conn = conns.get(SOCKS_PORT, 0) + conns.get(HTTP_PORT, 0)
    # nftables raw counters (real-time, для скорости)
    nft_down, nft_up = proxy_manager.get_live_traffic()
    # DB last row (график не дёргается)
    last = db_q(
        "SELECT collected_at, total_downlink, total_uplink FROM traffic_history ORDER BY id DESC LIMIT 1"
    )
    return jsonify(
        downlink=last[0]["total_downlink"] if last else 0,
        uplink=last[0]["total_uplink"] if last else 0,
        nft_down_raw=nft_down,
        nft_up_raw=nft_up,
        active_outbounds=0,
        active_connections=total_conn,
        socls_conns=conns.get(SOCKS_PORT, 0),
        http_conns=conns.get(HTTP_PORT, 0),
    )


@api_bp.route("/traffic/history")
def api_traffic_history():
    """GET /api/traffic/history?limit= — история трафика за последние N часов."""
    limit = request.args.get("limit", type=int, default=900)
    # усредняем до точек для графика — группируем по минутам
    rows = db_q(
        """SELECT
            collected_at,
            total_downlink,
            total_uplink,
            active_outbounds,
            active_connections
        FROM traffic_history
        ORDER BY id DESC LIMIT ?""",
        (limit,),
    )
    points = []
    for r in reversed(rows):
        points.append({
            "t": r["collected_at"],
            "down": r["total_downlink"],
            "up": r["total_uplink"],
            "conn": r["active_connections"],
        })
    return jsonify(points=points)


# ─── Active connections ───


@api_bp.route("/connections/list")
def api_connections_list():
    """GET /api/connections/list — список активных TCP-соединений через прокси."""
    conns = list_active_connections()
    return jsonify(connections=conns, total=len(conns))


@api_bp.route("/connections/close", methods=["POST"])
def api_connections_close():
    """POST /api/connections/close — закрыть соединение с указанным remote IP:PORT.
    Body: {remote_host, remote_port, local_port?}"""
    body = request.get_json(silent=True) or {}
    rh = body.get("remote_host", "").strip()
    rp = body.get("remote_port", 0)
    lp = body.get("local_port")
    if not rh or not rp:
        return jsonify(error="remote_host and remote_port required"), 400
    ok = close_connection(rh, int(rp), lp)
    add_log("INFO", f"Close connection {rh}:{rp} -> {'ok' if ok else 'failed'}")
    return jsonify(success=ok)


@api_bp.route("/connections/traffic")
def api_connections_traffic():
    """GET /api/connections/traffic — трафик сгруппированный по IP клиента."""
    conns = list_active_connections()
    per_ip = {}
    for c in conns:
        ip = c.get("remote", "")
        if not ip or ip == "0.0.0.0":
            continue
        if ip not in per_ip:
            per_ip[ip] = {"ip": ip, "connections": 0, "bytes_down": 0, "bytes_up": 0}
        per_ip[ip]["connections"] += 1
        per_ip[ip]["bytes_down"] += c.get("bytes_out", 0)
        per_ip[ip]["bytes_up"] += c.get("bytes_in", 0)
    return jsonify(clients=sorted(per_ip.values(), key=lambda x: x["bytes_down"], reverse=True))


@api_bp.route("/connections/flush", methods=["POST"])
def api_connections_flush():
    """POST /api/connections/flush — закрыть все активные соединения через прокси."""
    killed = flush_all_connections()
    add_log("INFO", f"Flushed {killed} connections")
    return jsonify(success=True, killed=killed)
