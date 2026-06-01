#!/usr/bin/env python3
"""VLESS Manager — Сервис для управления VLESS профилями прокси.

Точка входа: инициализирует БД, запускает фоновые задачи и стартует сервер.
"""

import threading

from app import create_app
from app.db import init_db, db_q
from app.utils import enrich_all_unknown_countries
from app.xray_configurator import xray_configurator
from app.proxy_manager import proxy_manager

app = create_app()

if __name__ == "__main__":
    init_db()
    rows = db_q("SELECT key, value FROM settings ORDER BY key")
    print("  Settings loaded:")
    for r in rows:
        print(f"    {r['key']}: {r['value'][:60]}")

    xray_configurator.apply_all()

    threading.Thread(target=enrich_all_unknown_countries, daemon=True).start()
    threading.Thread(target=proxy_manager.background_checker, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=False)
