#!/usr/bin/env python3
"""VLESS Manager — Сервис для управления VLESS профилями прокси.

Точка входа: инициализирует БД, запускает фоновые задачи и стартует сервер.
"""

import os
import signal
import sys
import threading
from pathlib import Path

from app import create_app
from app.db import init_db, db_q, Settings
from app.utils import enrich_all_unknown_countries
from app.xray_configurator import xray_configurator
from app.proxy_manager import proxy_manager


def _on_shutdown(signum, frame):
    proxy_manager.kill_all_xray_children()
    sys.exit(0)


app = create_app()

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _on_shutdown)
    signal.signal(signal.SIGINT, _on_shutdown)

    init_db()
    rows = db_q("SELECT key, value FROM settings ORDER BY key")
    print("  Settings loaded:")
    for r in rows:
        print(f"    {r['key']}: {r['value'][:60]}")

    if Path(Settings.xray_bin()).is_file():
        xray_configurator.apply_all()
    else:
        print(f"  Xray binary not found at {Settings.xray_bin()} — skipping apply_all")

    threading.Thread(target=enrich_all_unknown_countries, daemon=True).start()
    threading.Thread(target=proxy_manager.background_checker, daemon=True).start()
    proxy_manager.start_traffic_collector()
    app.run(host="0.0.0.0", port=5000, debug=False)
