"""Работа с SQLite: инициализация схемы, запросы, настройки."""

import json
import sqlite3
import threading
import time
from pathlib import Path

from config import DATABASE, ETC_XRAY_CONFIG, DEFAULT_XRAY_CONFIG
from config import SOCKS_PORT, HTTP_PORT, API_PORT


def _sqlite_connect() -> sqlite3.Connection:
    """Открывает подключение и выставляет PRAGMA (один раз на соединение)."""
    conn = sqlite3.connect(str(DATABASE), timeout=15)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA mmap_size=67108864")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=-4000")
    conn.row_factory = sqlite3.Row
    return conn


def _get_conn() -> sqlite3.Connection:
    """Новое подключение к БД (для длинных батчевых операций, закрывает сам вызов)."""
    return _sqlite_connect()


# Соединение на поток: прогон из 1500 прокси делает тысячи запросов, и открывать
# SQLite + выполнять 5 PRAGMA на каждый было заметной долей времени стадии.
_tls = threading.local()


def _thread_conn() -> sqlite3.Connection:
    """Подключение, привязанное к текущему потоку (переиспользуется между запросами)."""
    conn = getattr(_tls, "conn", None)
    if conn is None:
        conn = _sqlite_connect()
        _tls.conn = conn
    return conn


def db_q(sql: str, params: tuple | list = ()) -> list[sqlite3.Row]:
    """Выполняет SQL-запрос с параметрами, коммитит и возвращает результаты.
    При SQLITE_BUSY повторяет до 5 раз с экспоненциальной задержкой."""
    conn = _thread_conn()
    for attempt in range(5):
        try:
            c = conn.cursor()
            c.execute(sql, params)
            conn.commit()
            return c.fetchall()
        except sqlite3.OperationalError as e:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            if "busy" in str(e).lower() and attempt < 4:
                time.sleep(0.1 * (2**attempt))
                continue
            raise


# Эталонная схема таблиц — все ожидаемые колонки и их типы
_SCHEMA = {
    "proxies": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("link", "TEXT UNIQUE"),
        ("host", "TEXT"),
        ("port", "INTEGER"),
        ("country", "TEXT"),
        ("country_verified", "INTEGER DEFAULT 0"),
        ("status", "TEXT DEFAULT 'pending'"),
        ("latency", "INTEGER DEFAULT 0"),
        ("added_at", "TIMESTAMP"),
        ("failed_since", "TIMESTAMP"),
        ("security", "TEXT DEFAULT ''"),
        ("latency_vless", "INTEGER DEFAULT 0"),
        ("speed_kbps", "INTEGER DEFAULT 0"),
        ("speed_max_kbps", "INTEGER DEFAULT 0"),
        # Когда скорость последний раз пытались измерить (успешно или нет) и
        # сколько раз подряд не получилось: по этим полям замеры ротируются,
        # чтобы «плохие» по скорости узлы не занимали первые места каждый прогон.
        ("speed_tested_at", "TIMESTAMP"),
        ("speed_fail_count", "INTEGER DEFAULT 0"),
        ("source_id", "INTEGER"),
        ("last_test_at", "TIMESTAMP"),
        ("last_error", "TEXT"),
        # Счётчик падений подряд и время следующей проверки: мёртвые профили
        # перепроверяются с нарастающей паузой, а не в каждом прогоне.
        ("fail_count", "INTEGER DEFAULT 0"),
        ("next_test_at", "TIMESTAMP"),
        ("last_ok_at", "TIMESTAMP"),
    ],
    "sources": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("name", "TEXT"),
        ("url", "TEXT UNIQUE"),
        ("type", "TEXT DEFAULT 'url'"),
        ("content", "TEXT"),
        ("last_import", "TIMESTAMP"),
        ("created_at", "TIMESTAMP"),
        ("last_status", "TEXT"),
        ("last_error", "TEXT"),
        # Счётчики последнего удачного импорта: показывают, почему у источника
        # может быть 0 профилей (все ссылки уже были в других источниках).
        ("last_added", "INTEGER DEFAULT 0"),
        ("last_duplicates", "INTEGER DEFAULT 0"),
        ("last_parsed", "INTEGER DEFAULT 0"),
    ],
    "logs": [
        ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        ("timestamp", "TIMESTAMP"),
        ("level", "TEXT"),
        ("message", "TEXT"),
        ("correlation_id", "TEXT"),
    ],
    "settings": [
        ("key", "TEXT PRIMARY KEY"),
        ("value", "TEXT"),
    ],
}

# Единственный источник значений по умолчанию. Отсюда их берут и init_db
# (запись в БД при первом запуске), и Settings.get для ключей, которых в БД
# ещё нет: иначе запасные значения в Settings расходились бы с БД и панель
# вела себя по-разному до и после первой записи настройки.
SETTING_DEFAULTS = {
    "xray_bin": "/usr/local/bin/xray",
    "xray_config_path": "",  # подставляется из default_xray_config_path() при init_db
    "proxy_listen": "0.0.0.0",
    # Порты inbound'ов Xray. Задаются в UI; смена требует перезапуска Xray
    # (inbounds и API переезжают на новые порты).
    "socks_port": str(SOCKS_PORT),
    "http_port": str(HTTP_PORT),
    "api_port": str(API_PORT),
    "max_active_proxies": "30",
    "safe_only_import": "false",
    "blocked_countries": "",
    # URL проверки: лёгкий plain-HTTP generate_204 у Cloudflare. Он реже
    # блокируется, чем gstatic, и не требует второго TLS-рукопожатия внутри
    # туннеля — проба отвечает быстрее и меньше узлов ложно считаются мёртвыми.
    "probe_url": "http://cp.cloudflare.com/generate_204",
    # Список кандидатов через перевод строки/запятую или JSON-массив.
    # Пусто — встроенный каталог из app/netcheck.py (Cloudflare, Google,
    # Firefox, GNOME, Microsoft). См. кнопку «Тест URL» в настройках.
    "probe_url_candidates": "",
    # Автоподбор URL проверки по результатам теста (можно отключить).
    "probe_url_auto": "true",
    # Последний ручной тест кандидатов (JSON для UI). Служебное состояние.
    "probe_url_last_test": "",
    # URL, который недавно реально отвечал ЧЕРЕЗ туннели (JSON: url+ts).
    # Прямая проверка из панели не должна перебивать доказанный туннельный URL:
    # панель может быть заблокирована, а exit-ноды — нет. Служебное состояние.
    "probe_url_verified": "",
    # Интервалы и тюнинг
    "check_interval_db": "1800",
    "check_interval_import": "10800",
    "vless_per_proxy_timeout": "3",
    "log_trim_every": "500",
    "log_keep": "2000",
    "geosite_rules": "[]",
    "geo_enabled": "true",
    "observatory_probe_interval": "10s",
    "speed_test_enabled": "true",
    "speed_test_max": "8",
    # Файл замера: Cloudflare отдаёт ровно запрошенное число байт и стабильно
    # доступен с большинства exit-нод. Google Code Archive и ftp.bit.nl
    # отваливались, из-за чего стадия скорости оставалась без данных.
    "speed_test_url": "https://speed.cloudflare.com/__down?bytes=10000000",
    # Запасные файлы замера: строки/запятые или JSON-массив. Пусто — каталог
    # app/netcheck.py. Недоступный файл пропускается в пределах прогона.
    "speed_test_url_candidates": "",
    "speed_test_min_sec": "10",
    # true — штатный замер через профили (пишет speed_kbps каждому узлу).
    # false — только прямой замер панели для сравнения; профилям скорость не
    # пишется, поэтому конфиг может остаться на старых замерах.
    "speed_use_profiles": "true",
    # Последний прямой замер (JSON): avg/max/bytes/elapsed/url/ts.
    "speed_direct_last": "",
    "apply_after_test": "true",
    "balancer_strategy": "random",
    "handshake_timeout": "5",
    "conn_idle": "300",
    "min_speed_mbps": "0",
    # Строгий отбор: в конфиг и подписку только профили с замером скорости.
    # 0 в min_speed_mbps такого требования не даёт: без порога незамеренные
    # допускаются как второй эшелон.
    "require_speed": "false",
    # Порог «свежести» профиля в конфиге/подписке, минут (0 = авто:
    # 2 × check_interval_db, не меньше 3 ч и не больше суток).
    "profile_max_age_min": "0",
    # Теги node* outbound, которые, по данным панели, уже живут в Xray.
    # Служебное состояние hot-reload: не для редактирования в UI.
    "applied_node_tags": "",
    "speed_test_adaptive_sec": "2",
    "sniffing_enabled": "true",
    "sniffing_dest_override": "http,tls",
    "sniffing_route_only": "true",
    # Таймаут одной пробы через туннель. Медленные/защищённые узлы не успевают
    # за 5 с, поэтому по умолчанию чуть больше — качество проверки важнее.
    "probe_timeout": "8",
    "xray_startup_retries": "15",
    "db_check_auto_cleanup": "false",
    "import_proxy": "",
    # Как проверять: сколько прокси пихать в один процесс Xray и когда сдаваться.
    # 128 — оптимум для большинства VPS: волна проверок идёт вдвое быстрее, чем
    # на 64, а память/CPU одного процесса Xray остаются умеренными.
    "check_batch_size": "128",
    # Параллельных TCP-проверок до запуска Xray (независимо от пачки: это
    # просто сокеты SYN, лишний запас ускоряет префильтр на больших базах).
    "tcp_prefilter_workers": "128",
    "tcp_prefilter": "true",
    # Префильтр пропускает медленные/защищённые серверы: SYN может идти долго.
    "tcp_prefilter_timeout": "3",
    # Сколько дополнительных попыток делать, прежде чем признать профиль мёртвым.
    "tcp_prefilter_retries": "1",
    "probe_retries": "1",
    "ping_samples": "3",
    "failed_backoff": "true",
    # Бюджет стадии скорости: 20 минут хватает на speed_test_max профилей
    # по 10 секунд с запасом на таймауты файлов замера.
    "speed_stage_budget_sec": "1200",
}


def _ensure_schema(conn: sqlite3.Connection) -> None:
    """Проверяет эталонную схему и добавляет недостающие таблицы/колонки."""
    c = conn.cursor()
    for table, columns in _SCHEMA.items():
        cols_sql = ", ".join(f"{name} {typ}" for name, typ in columns)
        c.execute(f"CREATE TABLE IF NOT EXISTS {table} ({cols_sql})")
        existing = {
            row[1] for row in c.execute(f"PRAGMA table_info({table})").fetchall()
        }
        for col_name, col_type in columns:
            if col_name not in existing:
                try:
                    c.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}")
                except sqlite3.OperationalError:
                    pass


_MIGRATIONS = [
    {
        "version": 1,
        "description": "Обновление дефолтов traffic_collect_interval, traffic_history_hours",
        "sql": [
            "UPDATE settings SET value='2' WHERE key='traffic_collect_interval'",
            "UPDATE settings SET value='0.5' WHERE key='traffic_history_hours'",
        ],
    },
    {
        "version": 2,
        "description": "allowed_countries → blocked_countries (смена allowlist на blocklist)",
        "sql": [],
    },
    {
        "version": 3,
        "description": "Удаление истории трафика и nft-счётчиков (графики убраны из UI)",
        "sql": [
            "DELETE FROM settings WHERE key IN ('traffic_collect_interval', 'traffic_history_hours')",
            "DROP TABLE IF EXISTS traffic_history",
        ],
    },
    {
        "version": 4,
        "description": "speed_test_url: недоступные российские зеркала → глобальный CDN",
        "sql": [
            "UPDATE settings SET value='https://speed.cloudflare.com/__down?bytes=10000000' "
            "WHERE key='speed_test_url' AND value IN "
            "('http://speedtest.selectel.ru/10MB', 'http://speedtest.tele2.net/10MB')",
        ],
    },
    {
        "version": 5,
        "description": "speed_test_url: Cloudflare → Google 10MB (стабильный тест максимума)",
        "sql": [
            "UPDATE settings SET value="
            "'https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/jquery-speedtest/10MB.txt' "
            "WHERE key='speed_test_url' AND value="
            "'https://speed.cloudflare.com/__down?bytes=10000000'",
        ],
    },
    {
        # Проверка перестала доходить до стадии скорости: gstatic/ftp.bit.nl
        # блокировались или отваливались, а таймауты были слишком жёсткими для
        # медленных узлов. Переводим старые дефолты на менее блокируемые URL и
        # более терпеливые таймауты. Пользовательские значения не трогаем.
        "version": 6,
        "description": (
            "URL проверки и замера на менее блокируемые сервисы, "
            "более терпеливые таймауты пробы и TCP-префильтра"
        ),
        "sql": [
            "UPDATE settings SET value='http://cp.cloudflare.com/generate_204' "
            "WHERE key='probe_url' AND value IN "
            "('https://www.gstatic.com/generate_204', "
            "'https://connectivitycheck.gstatic.com/generate_204', "
            "'https://www.google.com/generate_204')",
            "UPDATE settings SET value="
            "'https://speed.cloudflare.com/__down?bytes=10000000' "
            "WHERE key='speed_test_url' AND value IN "
            "('https://ftp.bit.nl/speedtest/10mb.bin', "
            "'https://storage.googleapis.com/google-code-archive-downloads/"
            "v2/code.google.com/jquery-speedtest/10MB.txt', "
            "'http://speedtest.selectel.ru/10MB', "
            "'http://speedtest.tele2.net/10MB', "
            "'http://cachefly.cachefly.net/100mb.test')",
            "UPDATE settings SET value='8' "
            "WHERE key='probe_timeout' AND value='5'",
            "UPDATE settings SET value='3' "
            "WHERE key='tcp_prefilter_timeout' AND value='2'",
            # Бюджета 120с хватало лишь на 12 замеров из 30: остальные профили
            # не получали скорость и выпадали из «только замеренных».
            "UPDATE settings SET value='600' "
            "WHERE key='speed_stage_budget_sec' AND value='120'",
        ],
    },
    {
        # Проверка шла долго: пачка 64 профиля на процесс Xray недогружала
        # сеть, а префильтр работал в 64 сокета. 128 + отдельные воркеры
        # префильтра заметно сокращают прогон; пользовательские значения не
        # трогаем (меняем только прежний дефолт 64).
        "version": 7,
        "description": (
            "Пачка проверки 64 → 128 профилей, отдельная параллельность "
            "TCP-префильтра (tcp_prefilter_workers)"
        ),
        "sql": [
            "UPDATE settings SET value='128' "
            "WHERE key='check_batch_size' AND value='64'",
        ],
    },
    {
        # 600с хватало на 22 замера из 30: таймауты файлов съедали бюджет.
        # Новый дефолт — 1200с, пользовательские значения не трогаем.
        "version": 8,
        "description": "speed_stage_budget_sec: 600 → 1200 секунд",
        "sql": [
            "UPDATE settings SET value='1200' "
            "WHERE key='speed_stage_budget_sec' AND value='600'",
        ],
    },
    {
        # Старые speed_max/speed_kbps оставались у уже упавших профилей и
        # показывали «макс» там, где скорость уже 0. Чистим один раз при старте.
        "version": 9,
        "description": "очистка устаревших speed_max/speed_kbps у нерабочих профилей",
        "sql": [
            "UPDATE proxies SET speed_kbps=0, speed_max_kbps=0 WHERE status != 'working'",
            "UPDATE proxies SET speed_max_kbps=0 WHERE COALESCE(speed_kbps, 0) = 0",
        ],
    },
]


def _run_migrations(c: sqlite3.Cursor) -> None:
    """Применяет миграции по version."""
    current = 0
    row = c.execute("SELECT value FROM settings WHERE key='schema_version'").fetchone()
    if row:
        current = int(row["value"])
    for m in _MIGRATIONS:
        if m["version"] > current:
            for sql in m.get("sql", []):
                c.execute(sql)

            if m["version"] == 2:
                _migrate_allowed_to_blocked(c)

            c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('schema_version', ?)",
                      (str(m["version"]),))
            from .utils import add_log
            add_log("INFO", f"Migration v{m['version']}: {m['description']}")


def _migrate_allowed_to_blocked(c: sqlite3.Cursor) -> None:
    """allowed_countries (allowlist) → blocked_countries (blocklist), v2."""
    from .utils import add_log

    row = c.execute("SELECT value FROM settings WHERE key='allowed_countries'").fetchone()
    old_val = row["value"].strip() if row else ""
    if old_val:
        add_log(
            "WARN",
            f"Migration v2: old 'allowed_countries' had value '{old_val[:80]}...'. "
            "Система фильтрации изменена с allowlist на blocklist. "
            "Старое значение удалено. Настройте блокировку стран заново в Settings → Country Filter.",
        )
    c.execute("DELETE FROM settings WHERE key='allowed_countries'")


def init_db() -> None:
    """Создаёт/дополняет таблицы и устанавливает настройки по умолчанию."""
    conn = _get_conn()
    c = conn.cursor()
    _ensure_schema(conn)

    c.execute("CREATE INDEX IF NOT EXISTS idx_proxies_status ON proxies(status)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_proxies_speed_kbps ON proxies(speed_kbps)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_proxies_latency ON proxies(latency)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_proxies_source_id ON proxies(source_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_proxies_failed_since ON proxies(failed_since)")

    # Заполняем security у старых строк, импортированных до появления колонки.
    from .vless import parse_vless

    c.execute("SELECT id, link FROM proxies WHERE security IS NULL OR security = ''")
    for row in c.fetchall():
        parsed = parse_vless(row["link"])
        if parsed:
            sec = parsed.get("security", "none") or "none"
            c.execute("UPDATE proxies SET security=? WHERE id=?", (sec, row["id"]))
        else:
            c.execute("UPDATE proxies SET security='none' WHERE id=?", (row["id"],))

    _run_migrations(c)

    defaults = dict(SETTING_DEFAULTS)
    # Путь к конфигу Xray зависит от файловой системы, поэтому вычисляется здесь,
    # а не лежит готовой строкой в SETTING_DEFAULTS.
    defaults["xray_config_path"] = str(default_xray_config_path())
    for k, v in defaults.items():
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))

    conn.commit()
    conn.close()

    # Стартовая чистка логов по настройкам
    from .utils import trim_logs_startup

    trim_logs_startup()


class Settings:
    """Работа с настройками из таблицы settings в БД."""

    # Настройки читаются в горячем цикле проверки (по несколько раз на прокси).
    # Каждое чтение — запрос в SQLite, поэтому значения кэшируются на пару секунд:
    # изменение через UI подхватывается почти сразу, а прогон за это не платит.
    _CACHE_TTL = 2.0
    _cache: dict[str, tuple[float, str]] = {}
    _cache_lock = threading.Lock()

    @classmethod
    def _cached(cls, key: str) -> str | None:
        """Возвращает значение из кэша, если оно ещё не устарело."""
        with cls._cache_lock:
            item = cls._cache.get(key)
        if item and (time.monotonic() - item[0]) < cls._CACHE_TTL:
            return item[1]
        return None

    @classmethod
    def _store(cls, key: str, value: str) -> None:
        """Кладёт значение в кэш с текущей меткой времени."""
        with cls._cache_lock:
            cls._cache[key] = (time.monotonic(), value)

    @classmethod
    def invalidate(cls, key: str | None = None) -> None:
        """Сбрасывает кэш настроек (одного ключа или целиком)."""
        with cls._cache_lock:
            if key is None:
                cls._cache.clear()
            else:
                cls._cache.pop(key, None)

    @staticmethod
    def get(key: str, default: str | None = None) -> str:
        """Возвращает значение настройки из БД.

        Если ключа в БД нет и `default` не задан явно, берётся значение из
        SETTING_DEFAULTS — так дефолты не расходятся между init_db и чтением.
        """
        cached = Settings._cached(key)
        if cached is not None:
            return cached
        rows = db_q("SELECT value FROM settings WHERE key=?", (key,))
        if rows:
            value = rows[0]["value"]
            Settings._store(key, value)
            return value
        return SETTING_DEFAULTS.get(key, "") if default is None else default

    @staticmethod
    def set(key: str, value: str) -> None:
        """Сохраняет значение настройки в БД."""
        db_q("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
        Settings.invalidate(key)

    @classmethod
    def xray_bin(cls) -> str:
        """Путь к бинарнику Xray из настроек."""
        return cls.get("xray_bin", "xray")

    @classmethod
    def proxy_listen(cls) -> str:
        """Адрес для SOCKS/HTTP inbounds (0.0.0.0 для LAN)."""
        return cls.get("proxy_listen", "0.0.0.0")

    @classmethod
    def _port(cls, key: str, fallback: int) -> int:
        """Порт из настроек с защитой от мусора и недопустимых значений."""
        try:
            value = int(str(cls.get(key, str(fallback))).strip())
        except (TypeError, ValueError):
            return fallback
        return value if 1 <= value <= 65535 else fallback

    @classmethod
    def socks_port(cls) -> int:
        """Порт SOCKS5 inbound (клиенты панели)."""
        return cls._port("socks_port", SOCKS_PORT)

    @classmethod
    def http_port(cls) -> int:
        """Порт HTTP inbound (клиенты панели и проверка)."""
        return cls._port("http_port", HTTP_PORT)

    @classmethod
    def api_port(cls) -> int:
        """Порт gRPC API Xray (горячее применение outbound)."""
        return cls._port("api_port", API_PORT)

    @classmethod
    def max_active_proxies(cls) -> int:
        """Максимальное количество активных прокси в конфиге."""
        return int(cls.get("max_active_proxies", "30"))

    @classmethod
    def safe_only_import(cls) -> bool:
        """True если импортировать только прокси с шифрованием (reality/tls)."""
        return cls.get("safe_only_import") == "true"

    @classmethod
    def blocked_countries(cls) -> str:
        """Список заблокированных стран (строка с кодами через запятую).
        Пустая строка — не блокировать никого (все страны разрешены)."""
        return cls.get("blocked_countries").strip()

    @classmethod
    def probe_url(cls) -> str:
        """URL для проверки работоспособности прокси (observatory)."""
        return cls.get("probe_url")

    @classmethod
    def probe_retries(cls) -> int:
        """Сколько дополнительных попыток пробы делать до приговора «мёртв».

        Медленные и защищённые узлы отвечают не с первой попытки: один повтор
        с увеличенным таймаутом поднимает процент найденных живых профилей.
        """
        return max(0, min(3, int(cls.get("probe_retries", "1"))))

    @classmethod
    def probe_url_auto(cls) -> bool:
        """True — подбирать URL проверки по результатам теста кандидатов."""
        return (cls.get("probe_url_auto", "true") or "").strip().lower() == "true"

    @classmethod
    def check_interval_db(cls) -> int:
        """Интервал проверки прокси из БД, секунд."""
        return int(cls.get("check_interval_db"))

    @classmethod
    def check_interval_import(cls) -> int:
        """Интервал импорт + проверка, секунд."""
        return int(cls.get("check_interval_import"))

    @classmethod
    def vless_per_proxy_timeout(cls) -> int:
        """Таймаут VLESS-теста одного прокси, секунд."""
        return int(cls.get("vless_per_proxy_timeout"))

    @classmethod
    def log_trim_every(cls) -> int:
        """Чистить логи каждые N записей."""
        return int(cls.get("log_trim_every"))

    @classmethod
    def log_keep(cls) -> int:
        """Оставлять последние N записей после чистки."""
        return int(cls.get("log_keep"))

    @classmethod
    def geosite_rules(cls) -> list[dict]:
        """Список geosite-правил для routing Xray (JSON-строка)."""
        import json

        raw = cls.get("geosite_rules")
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return []

    @classmethod
    def min_speed_kbps(cls) -> int:
        """Минимальная скорость профиля в kbps. 0 = фильтр отключён."""
        raw = cls.get("min_speed_mbps")
        try:
            mbps = float(raw)
            return int(mbps * 1000) if mbps > 0 else 0
        except (ValueError, TypeError):
            return 0

    @classmethod
    def require_speed(cls) -> bool:
        """True — в конфиг и подписку только профили с замером скорости."""
        return (cls.get("require_speed", "false") or "").strip().lower() == "true"

    @classmethod
    def profile_max_age_min(cls) -> int:
        """Явный порог свежести профиля в минутах. 0 = вычислить автоматически."""
        try:
            return max(0, int(cls.get("profile_max_age_min", "0")))
        except (TypeError, ValueError):
            return 0

    @classmethod
    def profile_freshness_minutes(cls) -> int:
        """Сколько минут успешный тест считается доказательством работоспособности.

        Конфиг и подписка берут только профили не старше этого порога: иначе
        «working» месячной давности продолжает уезжать клиентам, хотя узел
        давно мёртв. Авто-режим привязан к интервалу проверки из БД: две
        проверки подряд должны уложиться в порог, но не меньше 3 часов
        (полный прогон большой базы сам занимает часы) и не больше суток.
        """
        configured = cls.profile_max_age_min()
        if configured > 0:
            return max(10, min(10080, configured))
        interval_min = max(1, cls.check_interval_db() // 60)
        return max(180, min(1440, interval_min * 2))

    @classmethod
    def applied_node_tags(cls) -> list[str]:
        """Теги node*, которые панель уже отправила в работающий Xray."""
        try:
            raw = json.loads(cls.get("applied_node_tags", "") or "[]")
        except (ValueError, TypeError):
            return []
        if not isinstance(raw, list):
            return []
        return [t for t in raw if isinstance(t, str) and t.startswith("node")]

    @classmethod
    def set_applied_node_tags(cls, tags) -> None:
        """Запоминает фактически применённый набор node-тегов."""
        cls.set("applied_node_tags", json.dumps(sorted(set(tags))))

    @classmethod
    def speed_test_adaptive_sec(cls) -> int:
        """Через сколько секунд adaptive speed test проверяет порог."""
        return max(1, int(cls.get("speed_test_adaptive_sec")))

    @classmethod
    def speed_test_duration_sec(cls) -> int:
        """Длительность замера скорости ОДНОГО профиля, сек.

        Фиксированное окно: каждый профиль в стадии speed тестируется ровно
        столько секунд (файл при необходимости докачивается повторно).
        Ранний выход возможен только при включённом пороге min_speed_mbps.
        """
        return max(1, min(300, int(cls.get("speed_test_min_sec"))))

    @classmethod
    def speed_use_profiles(cls) -> bool:
        """True — штатный замер через профили; False — только прямой baseline."""
        return (cls.get("speed_use_profiles", "true") or "").strip().lower() == "true"

    @classmethod
    def speed_direct_last(cls) -> dict:
        """Последний прямой замер скорости (пустой dict, если не было)."""
        import json

        try:
            value = cls.get("speed_direct_last", "")
            data = json.loads(value) if value else {}
            return data if isinstance(data, dict) else {}
        except (ValueError, TypeError):
            return {}

    @classmethod
    def probe_timeout(cls) -> int:
        """Таймаут одной HTTP-пробы при массовой проверке (секунды).

        Это таймаут стадии проверки: рабочий туннель отвечает на
        generate_204 за 0.3–2 с, всё, что дольше, для эксплуатации нерабочее.
        """
        return max(1, min(60, int(cls.get("probe_timeout"))))

    @classmethod
    def check_batch_size(cls) -> int:
        """Сколько профилей проверять в одном процессе Xray.

        Один процесс на пачку вместо процесса на каждый прокси: запуск Xray
        стоит столько же на 64 inbounds, сколько на один, поэтому большая
        пачка ускоряет прогон почти линейно, пока хватает CPU/сети.
        """
        return max(4, min(256, int(cls.get("check_batch_size", "128"))))

    @classmethod
    def tcp_prefilter_workers(cls) -> int:
        """Сколько TCP-проверок делать параллельно до запуска Xray.

        Это независимый от пачки пул сокетов: префильтр проверяет тысячи
        адресов, и 64 воркера держали прогон заметно дольше сети.
        """
        return max(4, min(512, int(cls.get("tcp_prefilter_workers", "128"))))

    @classmethod
    def tcp_prefilter(cls) -> bool:
        """Проверять TCP-доступность server:port до запуска Xray."""
        return cls.get("tcp_prefilter", "true") == "true"

    @classmethod
    def tcp_prefilter_timeout(cls) -> float:
        """Таймаут TCP-префильтра, секунды (дробный)."""
        try:
            return max(0.5, min(10.0, float(cls.get("tcp_prefilter_timeout", "3"))))
        except (TypeError, ValueError):
            return 3.0

    @classmethod
    def tcp_prefilter_retries(cls) -> int:
        """Дополнительные попытки TCP-префильтра для медленных серверов.

        SYN к защищённым/удалённым узлам может идти дольше одного таймаута;
        без повтора такие профили выпадали из проверки как «tcp timeout».
        """
        return max(0, min(3, int(cls.get("tcp_prefilter_retries", "1"))))

    @classmethod
    def ping_samples(cls) -> int:
        """Сколько проб делать при проверке (медиана пишется в latency)."""
        return max(1, min(7, int(cls.get("ping_samples", "3"))))

    @classmethod
    def failed_backoff(cls) -> bool:
        """True — мёртвые профили перепроверяются с нарастающей паузой."""
        return cls.get("failed_backoff", "true") == "true"

    @classmethod
    def speed_stage_budget_sec(cls) -> int:
        """Общий бюджет стадии замера скорости, секунд (0 — без ограничения)."""
        try:
            return max(0, min(7200, int(cls.get("speed_stage_budget_sec", "1200"))))
        except (TypeError, ValueError):
            return 1200

    @classmethod
    def xray_startup_retries(cls) -> int:
        """Количество попыток дождаться старта Xray (каждая 0.05 с)."""
        return max(5, min(200, int(cls.get("xray_startup_retries"))))

    @classmethod
    def import_proxy(cls) -> str:
        """Прокси для импорта подписок (socks5://host:port или http://host:port).
        Пустая строка — напрямую. Приоритет: БД > env IMPORT_PROXY."""
        db_val = cls.get("import_proxy").strip()
        if db_val:
            return db_val
        import os
        return (os.environ.get("IMPORT_PROXY") or "").strip()

def default_xray_config_path() -> Path:
    """Определяет путь к конфигу Xray по умолчанию."""
    if ETC_XRAY_CONFIG.exists():
        return ETC_XRAY_CONFIG
    return DEFAULT_XRAY_CONFIG


def xray_config_path() -> Path:
    """Определяет актуальный путь к конфигу Xray с учётом настроек и автоисправления."""
    default_path = default_xray_config_path()
    configured = Settings.get("xray_config_path", "")
    if not configured:
        return default_path
    p = Path(configured)
    try:
        if p.exists():
            return p
    except Exception:
        pass
    if default_path.exists() and str(default_path) != configured:
        try:
            Settings.set("xray_config_path", str(default_path))
        except Exception:
            pass
    return default_path
