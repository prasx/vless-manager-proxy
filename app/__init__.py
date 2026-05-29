"""Фабрика Flask-приложения VLESS Manager."""

from pathlib import Path

from flask import Flask


def create_app():
    """Создаёт и возвращает настроенный Flask app."""
    root = Path(__file__).resolve().parent.parent
    app = Flask(
        __name__,
        template_folder=str(root / "templates"),
        static_folder=str(root / "static"),
        static_url_path="/static",
    )
    app.config["JSON_AS_ASCII"] = False

    from .routes.pages import pages_bp
    from .routes.api import api_bp

    app.register_blueprint(pages_bp)
    app.register_blueprint(api_bp)
    return app
