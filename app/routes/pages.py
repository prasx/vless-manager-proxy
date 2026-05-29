"""Маршруты для страниц (HTML)."""

from flask import Blueprint, render_template

from ..db import db_q

pages_bp = Blueprint("pages", __name__)


@pages_bp.route("/")
def index():
    """Главная страница Dashboard."""
    stats = db_q("SELECT status, COUNT(*) cnt FROM proxies GROUP BY status")
    s = {r["status"]: r["cnt"] for r in stats}
    return render_template(
        "index.html", total=sum(s.values()), working=s.get("working", 0)
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
