"""Генерация subscribe.txt для внешних клиентов."""

from .db import db_q, Settings
from .selection import config_rows
from .utils import add_log, moscow_str
from config import SUBSCRIBE_FILE


def _speed_label(kbps: int) -> str:
    """Человекочитаемая скорость из kbps."""
    if kbps >= 1000:
        return f"{kbps // 1000}.{kbps % 1000 // 100} Mbps"
    return f"{kbps} Kbps"


def update_subscribe_cache() -> None:
    """Собирает subscribe.txt с vless-ссылками + метаданными для внешних клиентов.

    Состав подписки — тот же отбор, что и для конфига Xray (app/selection.py):
    рабочие и свежие профили, замеренные впереди незамеренных. Раньше здесь
    был отдельный SQL, и подписка неизбежно расходилась с конфигом — ровно
    тот случай, когда «в конфиге есть, а в подписке нет» (и наоборот).
    """
    try:
        max_active = Settings.max_active_proxies()
        sel = config_rows(max_active)
        total_all = db_q("SELECT COUNT(*) c FROM proxies")[0]["c"]
        speeds = [r["speed_kbps"] for r in sel.rows if r["speed_kbps"] > 0]
        avg_speed = int(sum(speeds) / len(speeds)) if speeds else 0
        measured = sum(1 for r in sel.rows if r["speed_kbps"] > 0)
        probe_url = Settings.probe_url()
        now = moscow_str()

        lines = [
            "# profile-title: VLESS Manager",
            "# profile-update-interval: 1",
            f"# Updated: {now}",
            f"# Configs: {len(sel.rows)} / {sel.counts.get('working_total', 0)} working / {total_all} total",
            f"# Measured: {measured}/{len(sel.rows)} · fresh ≤{sel.fresh_minutes} min",
        ]
        if avg_speed:
            lines.append(f"# Avg speed: {_speed_label(avg_speed)}")
        blocked = Settings.blocked_countries()
        if blocked:
            lines.append(f"# Blocked: {blocked}")
        lines.append(f"# Probe: {probe_url}")
        if sel.fallback:
            reason = {
                "slow": "все замеренные профили ниже порога скорости",
                "unmeasured": "ни один профиль не замерен",
                "stale": "нет свежих профилей, используются устаревшие",
            }.get(sel.fallback, sel.fallback)
            lines.append(f"# Warning: fallback — {reason}")
        lines.append("")
        for r in sel.rows:
            link = r["link"]
            if "#" not in link:
                host_part = (
                    link.split("@")[1].split("?")[0].split(":")[0]
                    if "@" in link
                    else ""
                )
                name = host_part[:20]
                if r["country"]:
                    name = f"{r['country']}_{name}"
                link = f"{link}#{name}"
            lines.append(link)
        SUBSCRIBE_FILE.write_text("\n".join(lines), encoding="utf-8")
        add_log("DEBUG", f"Subscribe cache updated: {len(sel.rows)} proxies")
    except Exception as e:
        add_log("ERROR", f"Failed to update subscribe cache: {e}")
