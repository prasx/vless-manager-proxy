"""Маршруты для страниц (HTML)."""

from flask import Blueprint, render_template

pages_bp = Blueprint("pages", __name__)


@pages_bp.route("/")
def index():
    """Главная страница Dashboard.

    Статистика не передаётся в шаблон: дашборд наполняется через /api/status
    и /api/proxies, а агрегатные запросы здесь были лишней работой на каждый
    рендер.
    """
    return render_template("index.html")


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
