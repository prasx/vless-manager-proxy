import shutil, tempfile, threading
from pathlib import Path

import app.db as db
from app import create_app
from app.db import db_q, init_db, Settings

tmp = Path(tempfile.mkdtemp(prefix="vless-tables-"))
dst = tmp / "preview.db"
shutil.copy("proxies.db", dst)
db.DATABASE = dst
db._tls = threading.local()
init_db()
Settings.invalidate()

# Показать максимум скорости рядом со средней: в старой БД его ещё нет.
rows = db_q("SELECT id, speed_kbps FROM proxies WHERE speed_kbps > 0 ORDER BY id LIMIT 40")
for r in rows:
    db_q("UPDATE proxies SET speed_max_kbps=? WHERE id=?", (int(r["speed_kbps"] * 1.18), r["id"]))

app = create_app()
app.run(host="127.0.0.1", port=5083, debug=False, use_reloader=False, threaded=True)
