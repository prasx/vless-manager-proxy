"""Генерация subscribe.txt для внешних клиентов."""

from .db import db_q, Settings
from .utils import add_log, moscow_str
from config import SUBSCRIBE_FILE


def update_subscribe_cache() -> None:
    """Собирает subscribe.txt с vless-ссылками + метаданными для внешних клиентов."""
    try:
        max_active = Settings.max_active_proxies()
        allowed = Settings.allowed_countries()
        codes = (
            [c.strip() for c in allowed.split(",") if c.strip()] if allowed else []
        )
        if codes:
            placeholders = ",".join("?" * len(codes))
            country_sql = f"AND country IN ({placeholders})"
        else:
            placeholders = ""
            country_sql = ""
            codes = []
        min_kbps = Settings.min_speed_kbps()
        speed_sql = f"AND speed_kbps >= {min_kbps}" if min_kbps > 0 else ""
        sort_col = "speed_kbps > 0 DESC, speed_kbps DESC, latency_vless ASC"
        rows = db_q(
            f"SELECT link, country, speed_kbps FROM proxies WHERE status='working' AND latency_vless > 0 {country_sql} {speed_sql} ORDER BY {sort_col} LIMIT ?",
            codes + [max_active],
        )
        total_all = db_q("SELECT COUNT(*) c FROM proxies")[0]["c"]
        total_working = db_q(
            "SELECT COUNT(*) c FROM proxies WHERE status='working'"
        )[0]["c"]
        speeds = [r["speed_kbps"] for r in rows if r["speed_kbps"] > 0]
        avg_speed = int(sum(speeds) / len(speeds)) if speeds else 0
        probe_url = Settings.probe_url()
        now = moscow_str()
        lines = [
            "# profile-title: VLESS Manager",
            "# profile-update-interval: 1",
            f"# Updated: {now}",
            f"# Configs: {len(rows)} / {total_working} working / {total_all} total",
        ]
        if avg_speed:
            speed_str = (
                f"{avg_speed // 1000}.{avg_speed % 1000 // 100} Mbps"
                if avg_speed >= 1000
                else f"{avg_speed} Kbps"
            )
            lines.append(f"# Avg speed: {speed_str}")
        if allowed:
            lines.append(f"# Filter: {allowed}")
        lines.append(f"# Probe: {probe_url}")
        lines.append("")
        for r in rows:
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
        add_log("DEBUG", f"Subscribe cache updated: {len(rows)} proxies")
    except Exception as e:
        add_log("ERROR", f"Failed to update subscribe cache: {e}")
