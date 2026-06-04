"""Маршруты для страниц (HTML)."""

from flask import Blueprint, render_template

pages_bp = Blueprint("pages", __name__)


@pages_bp.route("/")
def index():
    """Главная страница Dashboard."""
    from ..db import db_q

    stats = db_q("SELECT status, COUNT(*) cnt FROM proxies GROUP BY status")
    s = {r["status"]: r["cnt"] for r in stats}
    fr = db_q(
        "SELECT COUNT(*) c FROM proxies WHERE status='failed' AND (failed_since IS NULL OR failed_since >= datetime('now', '-24 hours'))"
    )[0]["c"]
    ts = db_q("SELECT COUNT(*) c FROM proxies WHERE speed_kbps >= 5000")[0]["c"]
    return render_template(
        "index.html",
        total=sum(s.values()),
        working=s.get("working", 0),
        failed_recent=fr,
        top_speed=ts,
    )


@pages_bp.route("/logs")
def logs():
    """Страница логов."""
    return render_template("logs.html")


@pages_bp.route("/sources")
def sources_page():
    """Страница источников."""
    return render_template("sources.html")


@pages_bp.route("/settings")
def settings_page():
    """Страница настроек."""
    return render_template("settings.html")
