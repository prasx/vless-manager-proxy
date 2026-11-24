"""Оценка качества источников конфигов.

Источник — это не «список ссылок», а поставщик живых узлов. Пока он отдаёт
сотни профилей, из которых работает пять, его место в подписке под вопросом:
дешевле найти другой источник, чем каждый прогон тратить время на его мёртвые
адреса.

Оценка (0–100) складывается из того, что реально видно в БД:

    55 % — выход: доля рабочих профилей от всех, что пришли из источника;
    20 % — замеры: доля рабочих, у которых есть замер скорости;
    15 % — свежесть: доля рабочих с актуальным успешным тестом;
    10 % — импорт: последняя попытка импорта дошла до источника или нет.

Вердикт и рекомендация — не украшение, а следующий шаг оператора:
    healthy  — держать, основной источник;
    weak     — держать, но искать лучше;
    bad      — мало рабочих, искать замену;
    stale    — профили устарели: нужен перетест/переимпорт;
    broken   — импорт не проходит: связь или устаревший URL;
    inactive — профилей нет: импортировать или удалить источник.
"""

from __future__ import annotations

import threading
import time
from datetime import timedelta

from .db import Settings, db_q
from .utils import now_utc

_CACHE_TTL = 15.0
_CACHE: dict = {"ts": 0.0, "data": {}}
_LOCK = threading.Lock()

# Статусы импорта, при которых источник реально ответил.
_REACHED = {"ok", "not_modified", "empty"}
_FAILED = {"network_error", "http_error", "bad_url", "error"}

VERDICT_LABELS = {
    "healthy": "основной",
    "weak": "второй эшелон",
    "bad": "мало рабочих",
    "stale": "устарел",
    "broken": "импорт не проходит",
    "inactive": "нет профилей",
    "duplicate": "все дубли",
    "empty": "нет ссылок",
}

VERDICT_RECOMMENDATIONS = {
    "healthy": "держать: источник даёт живые узлы",
    "weak": "держать, но искать источник получше",
    "bad": "искать замену: из массы профилей живых слишком мало",
    "stale": "запустить перетест: профили устарели",
    "broken": "проверить связь и URL источника",
    "inactive": "импортировать или удалить источник",
    "duplicate": "новых профилей нет: все ссылки уже пришли из других источников",
    "empty": "источник не отдал ни одной vless-ссылки",
}


def _import_age_min(last_import) -> int | None:
    if not last_import:
        return None
    from .selection import age_minutes

    return age_minutes(last_import, now_utc())


def _score(
    total: int,
    working: int,
    measured: int,
    fresh: int,
    last_status: str | None,
) -> int:
    """Итоговая оценка источника 0–100 (веса — в docstring модуля)."""
    if total <= 0:
        return 0
    yield_r = working / total
    measured_r = measured / max(working, 1)
    fresh_r = fresh / max(working, 1)
    import_ok = 1.0 if (last_status in (None, "") or last_status in _REACHED) else 0.0
    if last_status in (None, ""):
        import_ok = 0.5  # источник без импорта: не наказываем и не хвалим
    return int(round(100 * (0.55 * yield_r + 0.20 * measured_r + 0.15 * fresh_r + 0.10 * import_ok)))


def _verdict(
    total: int,
    working: int,
    fresh: int,
    score: int,
    last_status: str | None,
    last_added: int = 0,
    last_duplicates: int = 0,
    last_parsed: int = 0,
) -> str:
    if total <= 0:
        if last_status in _FAILED:
            return "broken"
        if last_status in (None, ""):
            return "inactive"
        if last_parsed > 0 and last_duplicates > 0 and last_added == 0:
            return "duplicate"
        if last_status == "empty":
            return "empty"
        return "inactive"
    if working <= 0:
        # Импорт проходит, а живых нет — так же плохо, как сломанный импорт,
        # поэтому разделяем только по статусу загрузки.
        return "broken" if last_status in _FAILED else "bad"
    if last_status in _FAILED:
        return "broken"
    fresh_r = fresh / max(working, 1)
    if fresh_r < 0.25:
        return "stale"
    if score >= 55:
        return "healthy"
    if score >= 30:
        return "weak"
    return "bad"


def collect(force: bool = False) -> dict[int, dict]:
    """Статистика и оценка по каждому источнику (кэш на 15 секунд).

    Возвращает {source_id: {...}}. Источники без профилей тоже попадают сюда:
    «нет профилей» — это тоже состояние, о котором надо знать.
    """
    now = time.monotonic()
    with _LOCK:
        if not force and _CACHE["data"] and (now - _CACHE["ts"]) < _CACHE_TTL:
            return _CACHE["data"]

    fresh_min = Settings.profile_freshness_minutes()
    cutoff = (now_utc() - timedelta(minutes=fresh_min)).strftime("%Y-%m-%d %H:%M:%S")

    agg = {
        r["sid"]: dict(r)
        for r in db_q(
            """SELECT p.source_id AS sid,
                      COUNT(*) AS total,
                      COALESCE(SUM(CASE WHEN p.status='working' THEN 1 ELSE 0 END), 0) AS working,
                      COALESCE(SUM(CASE WHEN p.status='working' AND p.speed_kbps > 0 THEN 1 ELSE 0 END), 0) AS measured,
                      COALESCE(SUM(CASE WHEN p.status='working'
                                        AND COALESCE(p.last_ok_at, p.last_test_at) >= ? THEN 1 ELSE 0 END), 0) AS fresh,
                      AVG(CASE WHEN p.status='working' AND p.latency_vless > 0
                               THEN p.latency_vless END) AS avg_latency,
                      AVG(CASE WHEN p.speed_kbps > 0 THEN p.speed_kbps END) AS avg_speed
                 FROM proxies p GROUP BY p.source_id""",
            (cutoff,),
        )
    }
    sources = [dict(r) for r in db_q(
        "SELECT id, name, url, type, last_import, last_status, last_error, "
        "last_added, last_duplicates, last_parsed FROM sources"
    )]

    data: dict[int, dict] = {}
    for s in sources:
        sid = s["id"]
        a = agg.get(sid, {})
        total = int(a.get("total") or 0)
        working = int(a.get("working") or 0)
        measured = int(a.get("measured") or 0)
        fresh = int(a.get("fresh") or 0)
        score = _score(total, working, measured, fresh, s.get("last_status"))
        verdict = _verdict(
            total, working, fresh, score, s.get("last_status"),
            int(s.get("last_added") or 0),
            int(s.get("last_duplicates") or 0),
            int(s.get("last_parsed") or 0),
        )
        data[sid] = {
            "id": sid,
            "name": s.get("name") or f"#{sid}",
            "type": s.get("type") or "url",
            "total": total,
            "working": working,
            "measured": measured,
            "fresh": fresh,
            "score": score,
            "verdict": verdict,
            "verdict_label": VERDICT_LABELS[verdict],
            "recommendation": VERDICT_RECOMMENDATIONS[verdict],
            "avg_latency": int(a.get("avg_latency") or 0),
            "avg_speed_kbps": int(a.get("avg_speed") or 0),
            "last_status": s.get("last_status"),
            "last_error": s.get("last_error") or "",
            "last_added": int(s.get("last_added") or 0),
            "last_duplicates": int(s.get("last_duplicates") or 0),
            "last_parsed": int(s.get("last_parsed") or 0),
            "import_age_min": _import_age_min(s.get("last_import")),
        }

    with _LOCK:
        _CACHE["data"] = data
        _CACHE["ts"] = time.monotonic()
    return data


def priority_map() -> dict[int, int]:
    """Оценки источников для приоритета в отборе профилей."""
    return {sid: int(d["score"]) for sid, d in collect().items()}


def ranked() -> list[dict]:
    """Источники по убыванию качества: сверху — те, кем стоит держаться."""
    items = list(collect().values())
    items.sort(key=lambda d: (-d["score"], -d["working"], -d["total"], d["name"].lower()))
    return items


def invalidate() -> None:
    """Сбрасывает кэш (после импорта/теста, чтобы UI не показывал старьё)."""
    with _LOCK:
        _CACHE["ts"] = 0.0


def summary() -> dict:
    """Сводка по всем источникам для шапки страницы."""
    items = list(collect().values())
    return {
        "sources": len(items),
        "healthy": sum(1 for d in items if d["verdict"] == "healthy"),
        "attention": sum(1 for d in items if d["verdict"] in ("weak", "bad", "stale", "broken", "duplicate", "empty")),
        "inactive": sum(1 for d in items if d["verdict"] == "inactive"),
        "total": sum(d["total"] for d in items),
        "working": sum(d["working"] for d in items),
        "measured": sum(d["measured"] for d in items),
    }
