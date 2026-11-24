"""Единая политика допуска профилей в конфиг Xray и в подписку.

Зачем отдельный модуль: раньше SQL-выборка жила в двух местах
(`xray_configurator._proxy_link_rows` и `subscribe.update_subscribe_cache`)
и неизбежно расходилась. Отсюда и симптом «в подписке есть, в конфиге нет»
(и наоборот): подписка и работающий Xray собирались по разным правилам.

Что считается годным профилем (tier):

    1. measured — рабочий, свежий и с замером скорости (speed_kbps > 0);
    2. probed   — рабочий и свежий, но скорость ещё не замерена.

Measured всегда идут раньше probed и не вытесняются ими из топ-N. Это и есть
ответ на «в конфиг не попадают замеренные сервера»: незамеренный профиль не
может занять место замеренного, даже если лежит в БД раньше.

Правила допуска:

    * status='working' и latency_vless > 0 — профиль реально отвечал на пробу;
    * профиль свежий: последний успешный тест не старше `profile_max_age_min`
      (0 = авто: 2 × check_interval_db, не меньше 3 ч и не больше суток).
      «Рабочий» статус месячной давности — не доказательство: узел мог умереть,
      а панель продолжала отдавать его в конфиг и подписку;
    * при заданном min_speed_mbps профиль обязан быть замерен и проходить порог.
      Раньше неизмеренный (speed_kbps = 0) считался «подходящим» и занимал место
      рядом с замеренными — порог скорости при этом ничего не проверял;
    * битая ссылка (validate_link) не попадает никуда: иначе генератор конфига
      молча выбрасывал её, а failover считал «ожидаемой» и пересобирал конфиг
      каждые 30 секунд.

Если под строгие правила не подходит ни один профиль, включается явный
fallback в порядке «наименее плохой»: замеренные-но-медленнее-порога →
незамеренные → устаревшие. Это пишется в лог и видно в UI: пустой конфиг хуже
деградировавшего, но пользователь обязан видеть, что конфиг собран не по
строгим правилам.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .checker import validate_link
from .db import Settings, db_q
from .utils import now_utc
from .vless import parse_vless

# Коды стран в блок-листе сравниваются без учёта регистра.
_MAX_EXCLUDED_SAMPLES = 300


def node_tag(proxy_id: int) -> str:
    """Стабильный тег outbound для профиля.

    Раньше тег был позиционным (node0, node1, ...): после пересортировки
    (например, после замера скорости) тот же тег означал уже ДРУГОЙ профиль,
    а diff-синк видел «тег есть» и не переотправлял outbound. В итоге в
    работающем Xray оставались старые узлы, хотя на диске и в подписке были
    новые. Тег от id профиля эту связь фиксирует.
    """
    return f"node{int(proxy_id)}"


def _parse_ts(value) -> datetime | None:
    """Разбирает TIMESTAMP из SQLite (строка) или datetime в наивный UTC."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    text = str(value).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def age_minutes(value, now: datetime) -> int | None:
    """Возраст отметки в минутах; None — отметки нет (считаем устаревшим)."""
    ts = _parse_ts(value)
    if ts is None:
        return None
    return max(0, int((now - ts).total_seconds() // 60))


@dataclass
class Selection:
    """Результат допуска: строки для конфига/подписки и объяснение отбора."""

    rows: list[dict] = field(default_factory=list)
    counts: dict = field(default_factory=dict)
    fallback: str = ""  # "" | "unmeasured" | "stale" | "slow"
    fresh_minutes: int = 0
    limit: int = 0
    excluded: list[dict] = field(default_factory=list)
    strict: bool = False  # включён режим «только замеренные»

    @property
    def tags(self) -> list[str]:
        """Теги node* для строк (порядок — приоритет в конфиге)."""
        return [node_tag(r["id"]) for r in self.rows]

    def summary(self) -> str:
        """Одна строка для лога: сколько взято и что отсеяно."""
        c = self.counts
        parts = [
            f"в конфиг {len(self.rows)} из {c.get('working_total', 0)} рабочих",
            f"свежесть ≤{self.fresh_minutes}мин",
        ]
        if c.get("stale"):
            parts.append(f"устарело {c['stale']}")
        if c.get("slow"):
            parts.append(f"медленнее порога {c['slow']}")
        if c.get("unmeasured"):
            parts.append(f"без замера {c['unmeasured']}")
        if c.get("blocked"):
            parts.append(f"страна исключена {c['blocked']}")
        if c.get("invalid"):
            parts.append(f"битых ссылок {c['invalid']}")
        if self.strict:
            parts.append("только замеренные")
        return ", ".join(parts)

    def as_dict(self) -> dict:
        """JSON для /api/config/preview."""
        return {
            "limit": self.limit,
            "fresh_minutes": self.fresh_minutes,
            "fallback": self.fallback,
            "strict": self.strict,
            "counts": dict(self.counts),
            "selected": [
                {
                    "id": r["id"],
                    "host": r.get("host"),
                    "country": r.get("country") or "",
                    "source_id": r.get("source_id"),
                    "tier": r.get("tier", 2),
                    "tier_label": "замерен" if r.get("tier") == 1 else "только проба",
                    "speed_kbps": int(r.get("speed_kbps") or 0),
                    "latency_vless": int(r.get("latency_vless") or 0),
                    "age_min": r.get("age_min"),
                }
                for r in self.rows
            ],
            "excluded": self.excluded[:_MAX_EXCLUDED_SAMPLES],
        }


def _source_priority() -> dict[int, int]:
    """Оценка качества источников для приоритета незамеренных профилей."""
    try:
        from .source_quality import priority_map

        return priority_map()
    except Exception:  # noqa: BLE001 — приоритет источников не должен ронять отбор
        return {}


def config_rows(limit: int = 0) -> Selection:
    """Отбирает профили для конфига Xray и подписки (единое правило).

    `limit` > 0 — только первые N по приоритету (max_active_proxies).
    """
    fresh_min = Settings.profile_freshness_minutes()
    min_kbps = Settings.min_speed_kbps()
    require_speed = Settings.require_speed()
    blocked_raw = Settings.blocked_countries() or ""
    blocked = {c.strip().upper() for c in blocked_raw.split(",") if c.strip()}
    now = now_utc()

    counts = {
        "working_total": 0,
        "eligible": 0,
        "selected": 0,
        "stale": 0,
        "slow": 0,
        "unmeasured": 0,
        "blocked": 0,
        "invalid": 0,
    }
    excluded: list[dict] = []

    def exclude(row, reason: str, detail: str, age=None):
        src = row.get("source_id")
        excluded.append(
            {
                "id": row["id"],
                "host": row.get("host"),
                "source_id": src,
                "reason": reason,
                "detail": detail,
                "latency_vless": int(row.get("latency_vless") or 0),
                "speed_kbps": int(row.get("speed_kbps") or 0),
                "age_min": age,
            }
        )

    rows = db_q(
        "SELECT id, link, host, country, source_id, latency_vless, speed_kbps, "
        "last_test_at, last_ok_at FROM proxies "
        "WHERE status='working' AND COALESCE(latency_vless,0) > 0"
    )
    counts["working_total"] = len(rows)

    candidates: list[dict] = []
    stale_rows: list[dict] = []
    unmeasured_rows: list[dict] = []
    slow_rows: list[dict] = []

    for r in rows:
        link = (r["link"] or "").strip()
        parsed = parse_vless(link)
        bad = validate_link(parsed)
        if bad:
            counts["invalid"] += 1
            exclude(dict(r), "invalid", f"битая ссылка: {bad}")
            continue

        country = (r["country"] or "").upper()
        if country and country in blocked:
            counts["blocked"] += 1
            exclude(dict(r), "blocked", f"страна {country} исключена")
            continue

        age = age_minutes(r["last_ok_at"] or r["last_test_at"], now)
        fresh = age is not None and age <= fresh_min
        speed = int(r["speed_kbps"] or 0)
        item = {
            "id": r["id"],
            "link": link,
            "parsed": parsed,
            "host": r["host"],
            "country": r["country"] or "",
            "source_id": r["source_id"],
            "latency_vless": int(r["latency_vless"] or 0),
            "speed_kbps": speed,
            "age_min": age,
            "tier": 1 if speed > 0 else 2,
        }

        if not fresh:
            counts["stale"] += 1
            detail = (
                "нет ни одного успешного теста"
                if age is None
                else f"последний успешный тест {age} мин назад (порог {fresh_min})"
            )
            exclude(dict(r), "stale", detail, age)
            stale_rows.append(item)
            continue

        if speed <= 0 and (require_speed or min_kbps > 0):
            # Порог скорости нельзя подтвердить у незамеренного профиля, а в
            # строгом режиме он не допускается вообще.
            counts["unmeasured"] += 1
            detail = (
                "скорость не замерена, включён строгий отбор «только замеренные»"
                if require_speed
                else "скорость не замерена, а задан порог min_speed"
            )
            exclude(dict(r), "unmeasured", detail, age)
            unmeasured_rows.append(item)
            continue
        if min_kbps > 0 and speed < min_kbps:
            counts["slow"] += 1
            exclude(
                dict(r),
                "slow",
                f"скорость {speed / 1000:.1f} Mbps ниже порога {min_kbps / 1000:.1f} Mbps",
                age,
            )
            slow_rows.append(item)
            continue

        candidates.append(item)

    fallback = ""
    if not candidates:
        if slow_rows:
            # Замер есть, но всё ниже порога. Это по-прежнему «доступные и
            # понятные» узлы, в отличие от неизмеренных, поэтому в аварийном
            # режиме они предпочтительнее неизвестной скорости.
            candidates = slow_rows
            fallback = "slow"
        elif unmeasured_rows and not require_speed:
            # Есть живые и свежие, но нет ни одного замера (например, сломался
            # speed-стенд). Пустой конфиг хуже: берём незамеренные, но явно.
            candidates = unmeasured_rows
            fallback = "unmeasured"
        elif stale_rows:
            # Всё, что было рабочим, устарело (проверки не идут?). Берём самое
            # свежее из устаревшего, чтобы прокси не умер окончательно. В строгом
            # режиме устаревшие тоже обязаны иметь замер.
            measured_stale = (
                [r for r in stale_rows if r["speed_kbps"] > 0]
                if require_speed else stale_rows
            )
            if measured_stale:
                candidates = measured_stale
                fallback = "stale"

    priority = _source_priority()

    def sort_key(item: dict):
        return (
            item["tier"],
            -item["speed_kbps"],
            -priority.get(item["source_id"] or 0, 0),
            item["latency_vless"],
            item["id"],
        )

    candidates.sort(key=sort_key)
    counts["eligible"] = len(candidates)

    selected = candidates[:limit] if limit and limit > 0 else candidates
    counts["selected"] = len(selected)

    return Selection(
        rows=selected,
        counts=counts,
        fallback=fallback,
        fresh_minutes=fresh_min,
        limit=limit,
        excluded=excluded,
        strict=require_speed,
    )


def retest_targets(limit: int = 0) -> list[dict]:
    """Кандидаты на перепроверку: рабочие, чьё доказательство устарело.

    Используется кнопкой/циклом «актуализировать»: первыми идут профили,
    которые уже нельзя отдавать в конфиг (устаревшие), затем незамеренные.
    """
    fresh_min = Settings.profile_freshness_minutes()
    now = now_utc()
    rows = db_q(
        "SELECT id, host, latency_vless, speed_kbps, last_test_at, last_ok_at "
        "FROM proxies WHERE status='working' ORDER BY COALESCE(last_ok_at, last_test_at) ASC"
    )
    targets = []
    for r in rows:
        age = age_minutes(r["last_ok_at"] or r["last_test_at"], now)
        if age is None or age > fresh_min:
            targets.append(
                {
                    "id": r["id"],
                    "host": r["host"],
                    "age_min": age,
                    "reason": "устарел" if age is not None else "не тестировался",
                }
            )
        elif int(r["speed_kbps"] or 0) <= 0:
            targets.append(
                {"id": r["id"], "host": r["host"], "age_min": age, "reason": "нет замера"}
            )
        if limit and len(targets) >= limit:
            break
    return targets
