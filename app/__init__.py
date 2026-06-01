"""Фабрика Flask-приложения VLESS Manager."""

from pathlib import Path
import traceback

from flask import Flask


def _log_exception(app, exc):
    """Логирует неперехваченное исключение в таблицу logs."""
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    app.logger.error(tb)
    try:
        from .utils import add_log

        add_log("ERROR", f"Unhandled: {exc}")
    except Exception:
        pass


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

    @app.errorhandler(500)
    def handle_500(e):
        _log_exception(app, e)
        return {"error": "Internal server error"}, 500

    return app
