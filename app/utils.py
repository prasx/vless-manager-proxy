"""Утилиты: работа со временем, логирование, гео-определение страны."""

import json
import ssl
import threading
import time
from datetime import datetime
from zoneinfo import ZoneInfo
from typing import Optional

from .db import _get_conn, Settings
from config import MOSCOW_TZ, UTC_TZ

_current_cid: str = ""
_cid_lock = threading.Lock()


def set_correlation_id(cid: str) -> None:
    """Устанавливает correlation_id для всех последующих логов в этом потоке."""
    global _current_cid
    with _cid_lock:
        _current_cid = cid


def get_correlation_id() -> str:
    """Возвращает correlation_id текущего потока (пустая строка, если не задан)."""
    with _cid_lock:
        return _current_cid


def now_utc() -> datetime:
    """Наивный UTC datetime для хранения в БД (совместимость с SQLite datetime('now'))."""
    return datetime.now(UTC_TZ).replace(tzinfo=None)


def moscow_str(dt: Optional[datetime] = None) -> str:
    """Форматирование даты/времени в московском часовом поясе для отображения."""
    if dt is None:
        dt = datetime.now(MOSCOW_TZ)
    elif dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOSCOW_TZ)
    else:
        dt = dt.astimezone(MOSCOW_TZ)
    return dt.strftime("%Y-%m-%d %H:%M:%S %z")


def fmt_log(level: str, message: str) -> str:
    """Форматирует лог-сообщение: если message не JSON, оборачивает в JSON."""
    try:
        json.loads(message)
        return message
    except (json.JSONDecodeError, TypeError):
        pass
    return json.dumps({"msg": message}, ensure_ascii=False)


_log_insert_count = 0
_log_count_lock = threading.Lock()
_log_buffer: list = []
_log_buffer_lock = threading.Lock()
_log_flush_timer = None


def _flush_log_buffer():
    """Вставляет накопленные логи одним запросом."""
    global _log_buffer, _log_flush_timer
    with _log_buffer_lock:
        batch = _log_buffer[:]
        _log_buffer.clear()
        _log_flush_timer = None
    if not batch:
        return
    conn = _get_conn()
    try:
        conn.executemany(
            "INSERT INTO logs (timestamp, level, message, correlation_id) VALUES (?, ?, ?, ?)",
            batch,
        )
        conn.commit()
    except Exception:
        # БД могли удалить/закрыть (тесты, остановка процесса): потерять
        # отложенные логи неприятно, но падать в фоновом таймере — нельзя.
        pass
    finally:
        conn.close()
    with _log_count_lock:
        global _log_insert_count
        _log_insert_count += len(batch)
        do_trim = _log_insert_count % Settings.log_trim_every() == 0
    if do_trim:
        _trim_logs()


def add_log(level: str, message: str, correlation_id: str = "") -> None:
    """Добавляет запись в лог-таблицу БД. Батчит вставки для производительности."""
    global _log_flush_timer
    cid = correlation_id or get_correlation_id()
    msg = fmt_log(level, message)
    with _log_buffer_lock:
        _log_buffer.append((now_utc(), level, msg, cid or None))
        if _log_flush_timer is None:
            _log_flush_timer = threading.Timer(0.3, _flush_log_buffer)
            _log_flush_timer.daemon = True
            _log_flush_timer.start()


def _trim_logs() -> None:
    """Оставляет только последние N записей в логах."""
    keep = Settings.log_keep()
    conn = _get_conn()
    try:
        conn.execute(
            "DELETE FROM logs WHERE id NOT IN (SELECT id FROM logs ORDER BY id DESC LIMIT ?)",
            (keep,),
        )
        conn.commit()
    finally:
        conn.close()


def flush_logs_now() -> None:
    """Сбрасывает буфер логов синхронно и отменяет отложенный таймер.

    Нужен при остановке процесса и в тестах: иначе таймер дозаписи может
    сработать уже после смены/удаления файла БД и записать логи не туда.
    """
    global _log_flush_timer
    with _log_buffer_lock:
        timer = _log_flush_timer
        _log_flush_timer = None
    if timer is not None:
        try:
            timer.cancel()
        except Exception:
            pass
    _flush_log_buffer()


def trim_logs_startup() -> None:
    """Принудительная чистка логов при старте (учитывает настройки)."""
    _trim_logs()


# ─── Определение страны ───
#
# Раньше страна определялась для ВСЕХ профилей последовательно, по одному
# запросу на прокси, прямо внутри эксклюзивного прогона: 900 адресов = ~4 минуты,
# в которые пинг и замер скорости просто стояли. Теперь:
#   * ip-api вызывается батчами (до 100 адресов за запрос);
#   * запросы идут в фоновом потоке и не держат блокировку замеров;
#   * результат кешируется по IP, неудачи — с отрицательным кешем, чтобы
#     мёртвый хост не опрашивался в каждом прогоне;
#   * повторно проверяются только ещё не верифицированные профили.

_GEO_OK_TTL = 30 * 24 * 3600      # успешный ответ живёт месяц
_GEO_NEG_TTL = 6 * 3600           # неудачу не повторяем 6 часов
_GEO_HOST_TTL = 6 * 3600          # DNS-резолв хоста
_GEO_BATCH = 100
_GEO_BATCH_MIN_INTERVAL = 4.1     # не чаще 15 батч-запросов в минуту
# Сколько не трогать ip-api.com после первого таймаута: сервер либо блокирует
# его, либо он лежит — ждать по 10 с на каждый батч бессмысленно.
_GEO_IPAPI_COOLDOWN = 600
_geo_ipapi_down_until = 0.0
# Резервный сервис определения страны: HTTPS и не блокируется там, где
# ip-api.com (только HTTP) недоступен. Один IP за запрос, поэтому параллельно.
_GEO_FALLBACK_URL = "https://api.country.is/{ip}"
_GEO_FALLBACK_PARALLEL = 10
_GEO_SSL = ssl.create_default_context()
_GEO_SSL.check_hostname = False
_GEO_SSL.verify_mode = ssl.CERT_NONE

_geo_ip_cache: dict[str, tuple[float, str]] = {}
_geo_neg_cache: dict[str, float] = {}
_geo_host_cache: dict[str, tuple[float, str]] = {}
_geo_lock = threading.Lock()
_geo_last_request = 0.0

# Один прогон обогащения за раз; повторный вызов во время работы игнорируется.
_enrich_lock = threading.Lock()


def _geo_cached(cache: dict, key: str, ttl: float):
    """Возвращает значение geo-кеша, если оно не старше ttl."""
    with _geo_lock:
        item = cache.get(key)
    if item and (time.time() - item[0]) < ttl:
        return item[1]
    return None


def _geo_store_ip(ip: str, cc: str) -> None:
    """Запоминает успешную страну IP и снимает негативную метку."""
    with _geo_lock:
        _geo_ip_cache[ip] = (time.time(), cc)
        _geo_neg_cache.pop(ip, None)


def _geo_mark_negative(ip: str) -> None:
    """Запоминает, что для IP не удалось определить страну."""
    with _geo_lock:
        _geo_neg_cache[ip] = time.time()


def resolve_host(host: str) -> str:
    """Резолвит hostname в IP с кешированием (пустая строка — не резолвится)."""
    cached = _geo_cached(_geo_host_cache, host, _GEO_HOST_TTL)
    if cached is not None:
        return cached
    try:
        import socket

        ip = socket.gethostbyname(host)
    except Exception:
        ip = ""
    with _geo_lock:
        _geo_host_cache[host] = (time.time(), ip)
    if not ip:
        _geo_mark_negative(host)
    return ip


def _ipapi_batch(ips: list[str]) -> dict[str, str]:
    """POST /batch в ip-api.com: до 100 адресов за один запрос.

    На части серверов ip-api.com (только HTTP) недоступен и стабильно отдаёт
    таймаут. После первого такого таймаута 10 минут ходим сразу в HTTPS-резерв
    api.country.is: не ждём по 10 секунд на каждый батч и не засоряем логи.
    """
    global _geo_last_request, _geo_ipapi_down_until
    if not ips:
        return {}
    now = time.time()
    with _geo_lock:
        down_until = _geo_ipapi_down_until
    if now < down_until:
        return _country_is_batch(ips)
    wait = _GEO_BATCH_MIN_INTERVAL - (now - _geo_last_request)
    if wait > 0:
        time.sleep(wait)
    from urllib.request import Request, urlopen

    payload = json.dumps(
        [{"query": ip, "fields": "status,countryCode,query"} for ip in ips]
    ).encode()
    req = Request(
        "http://ip-api.com/batch",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    _geo_last_request = time.time()
    try:
        with urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
    except Exception as e:  # noqa: BLE001
        with _geo_lock:
            _geo_ipapi_down_until = time.time() + _GEO_IPAPI_COOLDOWN
        add_log(
            "WARN",
            f"ip-api.com недоступен ({e}) — {_GEO_IPAPI_COOLDOWN // 60} мин "
            "определяем страны через HTTPS-резерв api.country.is",
        )
        return _country_is_batch(ips)
    out: dict[str, str] = {}
    if isinstance(data, list):
        for item in data:
            query = item.get("query") or ""
            if item.get("status") == "success" and item.get("countryCode"):
                out[query] = item["countryCode"]
    return out


def _country_is_batch(ips: list[str]) -> dict[str, str]:
    """Резервное определение страны через HTTPS api.country.is (по одному IP).

    Возвращает {ip: CC} только для успешных ответов: вызывающий код сам
    помечает остальные как негативный кеш.
    """
    from concurrent.futures import ThreadPoolExecutor
    from urllib.request import Request, urlopen

    def lookup(ip: str) -> tuple[str, str]:
        """Запрашивает страну одного IP у api.country.is."""
        try:
            req = Request(
                _GEO_FALLBACK_URL.format(ip=ip),
                headers={"User-Agent": "Mozilla/5.0"},
            )
            with urlopen(req, timeout=6, context=_GEO_SSL) as r:
                data = json.loads(r.read().decode())
            cc = str(data.get("country") or "").upper()
            return ip, cc if len(cc) == 2 else ""
        except Exception:
            return ip, ""

    out: dict[str, str] = {}
    if not ips:
        return out
    workers = max(2, min(_GEO_FALLBACK_PARALLEL, len(ips)))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="geo-fallback") as pool:
        for ip, cc in pool.map(lookup, ips):
            if cc:
                out[ip] = cc
    if out:
        add_log("DEBUG", f"api.country.is определил страны для {len(out)}/{len(ips)} IP")
    return out


def _geo_targets(limit: int | None = None) -> list[dict]:
    """Рабочие профили, для которых страна ещё не верифицирована.

    Мёртвые и непроверенные профили не тратят DNS/ip-api: их страна никому
    не нужна, пока они не станут working. После проверки конвейер сам
    запускает обогащение только что появившихся рабочих.
    """
    from .db import db_q

    sql = (
        "SELECT id, host, country, COALESCE(country_verified, 0) AS verified "
        "FROM proxies WHERE status = 'working' "
        "AND COALESCE(country_verified, 0) = 0 ORDER BY id ASC"
    )
    if limit:
        sql += " LIMIT ?"
        return [dict(r) for r in db_q(sql, (limit,))]
    return [dict(r) for r in db_q(sql)]


def enrich_countries_once(limit: int | None = None) -> int:
    """Один проход обогащения: батчи запросов + один батч записи в БД.

    Возвращает число исправленных стран. Рассчитан на фоновый поток:
    блокировку замеров не держит и не требует.
    """
    rows = _geo_targets(limit)
    if not rows:
        return 0

    # host → ip: уникальные хосты резолвятся параллельно (на 1500 профилей
    # последовательный gethostbyname занимал минуты и всё это время висел поток).
    hosts = sorted({r["host"] for r in rows if r["host"]})
    host_to_ip: dict[str, str] = {}
    if hosts:
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=min(20, len(hosts)),
                                thread_name_prefix="geo-dns") as pool:
            for host, ip in zip(hosts, pool.map(resolve_host, hosts), strict=True):
                if ip:
                    host_to_ip[host] = ip

    unknown = [
        ip
        for ip in {*host_to_ip.values()}
        if _geo_cached(_geo_ip_cache, ip, _GEO_OK_TTL) is None
        and not _neg_recent(ip)
    ]
    for start in range(0, len(unknown), _GEO_BATCH):
        chunk = unknown[start:start + _GEO_BATCH]
        for ip, cc in _ipapi_batch(chunk).items():
            _geo_store_ip(ip, cc)
        for ip in chunk:
            if _geo_cached(_geo_ip_cache, ip, _GEO_OK_TTL) is None:
                _geo_mark_negative(ip)

    updates: list[tuple] = []
    for r in rows:
        ip = host_to_ip.get(r["host"], "")
        cc = _geo_cached(_geo_ip_cache, ip, _GEO_OK_TTL) if ip else None
        if not cc:
            continue
        if r["country"] == cc:
            updates.append((None, None, r["id"]))  # только флаг верификации
        else:
            updates.append((cc, 1, r["id"]))
    if not updates:
        return 0

    corrected = 0
    conn = _get_conn()
    try:
        for item in updates:
            cc, flag, pid = item[0], item[1], item[2]
            if cc is None:
                conn.execute("UPDATE proxies SET country_verified=1 WHERE id=?", (pid,))
            else:
                conn.execute(
                    "UPDATE proxies SET country=?, country_verified=? WHERE id=?",
                    (cc, flag or 1, pid),
                )
                corrected += 1
        conn.commit()
    finally:
        conn.close()
    if corrected:
        add_log(
            "INFO",
            f"Country corrected for {corrected}/{len(rows)} proxies via ip-api.com",
        )
    return corrected


def _neg_recent(key: str) -> bool:
    """True, если для ключа недавно была неудача и можно не повторять запрос."""
    with _geo_lock:
        ts = _geo_neg_cache.get(key)
    return bool(ts and (time.time() - ts) < _GEO_NEG_TTL)


def enrich_all_unknown_countries():
    """Синхронный проход обогащения (старое имя, неблокирующий для замеров)."""
    if not _enrich_lock.acquire(blocking=False):
        return
    try:
        enrich_countries_once()
    except Exception as e:  # noqa: BLE001
        add_log("DEBUG", f"Country enrichment failed: {e}")
    finally:
        _enrich_lock.release()


def schedule_country_enrichment() -> bool:
    """Запускает обогащение стран в фоне. True — поток запущен.

    Вызывается из конвейера: раньше страна определялась прямо в прогоне и
    пинг/скорость ждали эти минуты. Теперь прогон идёт дальше, а страны
    досыпаются в фоне.
    """
    if _enrich_lock.locked():
        return False

    def run():
        """Фоновый проход обогащения стран."""
        enrich_all_unknown_countries()

    threading.Thread(target=run, daemon=True, name="geo-enrich").start()
    return True


def _get_conntrack_map():
    """Парсит conntrack, возвращает {(client_ip, client_port): (bytes_to_client, bytes_from_client)}.
    Тихий возврат {} если conntrack недоступен."""
    import os
    import re
    import subprocess
    proxy_ports_str = [str(Settings.socks_port()), str(Settings.http_port())]
    result = {}
    if os.name == "nt":
        return result
    try:
        r = subprocess.run(
            ["conntrack", "-L"],
            capture_output=True, text=True, timeout=5,
        )
        lines = r.stdout.splitlines()
    except Exception:
        try:
            with open("/proc/net/nf_conntrack") as f:
                lines = f.read().splitlines()
        except Exception:
            return result

    ports_filter = tuple(f"dport={p}" for p in proxy_ports_str)
    for line in lines:
        if not any(p in line for p in ports_filter):
            continue
        vals = re.findall(r'bytes=(\d+)', line)
        if len(vals) < 2:
            continue
        port_pattern = '|'.join(proxy_ports_str)
        m = re.search(rf'src=([^\s]+)\s+.*?sport=(\d+)\s+dport=({port_pattern})', line)
        if not m:
            continue
        client_ip = m.group(1)
        client_port = int(m.group(2))
        bytes_to_client = int(vals[1])
        bytes_from_client = int(vals[0])
        key = (client_ip, client_port)
        existing = result.get(key, (0, 0))
        result[key] = (existing[0] + bytes_to_client, existing[1] + bytes_from_client)
    return result


def list_active_connections(proxy_ports: list[int] | None = None) -> list[dict]:
    """Возвращает детальный список TCP-соединений через прокси-порты.
    Каждый элемент: {pid, process, local, local_port, remote, remote_port, status, direction, bytes_in, bytes_out}"""
    if proxy_ports is None:
        proxy_ports = [Settings.socks_port(), Settings.http_port()]
    import os
    import subprocess

    is_win = os.name == "nt"
    result = []

    try:
        if is_win:
            pid_map = _win_pid_map()
            r = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True, text=True, timeout=5,
            )
            for line in r.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) < 5:
                    continue
                proto = parts[0].upper()
                if proto not in ("TCP",):
                    continue
                local = parts[1]
                remote = parts[2]
                status = parts[3]
                pid_str = parts[4]
                pid = int(pid_str) if pid_str.isdigit() else 0
                process_name = pid_map.get(pid, "")

                local_host, local_port = _split_addr_port(local)
                remote_host, remote_port = _split_addr_port(remote)

                # Показываем только ESTABLISHED + связанные с прокси
                if status.upper() != "ESTABLISHED":
                    continue
                is_client = local_port in proxy_ports or remote_port in proxy_ports
                if is_client:
                    result.append(dict(
                        pid=pid, process=process_name,
                        local=local_host, local_port=local_port,
                        remote=remote_host, remote_port=remote_port,
                        status=status, direction="up" if remote_port in proxy_ports else "down",
                        bytes_in=0, bytes_out=0,
                    ))
        else:
            # Linux: ss -antp (с -p для PID). Если нет прав — fallback без -p
            try:
                r = subprocess.run(
                    ["ss", "-antp"],
                    capture_output=True, text=True, timeout=5,
                )
                if r.returncode != 0:
                    r = subprocess.run(
                        ["ss", "-ant"],
                        capture_output=True, text=True, timeout=5,
                    )
            except Exception:
                r = subprocess.run(
                    ["ss", "-ant"],
                    capture_output=True, text=True, timeout=5,
                )
            for line in r.stdout.splitlines():
                line = line.strip()
                if not line or line[0].isalpha() and not line.startswith("ESTAB") and not line.startswith("LISTEN"):
                    continue
                parts = line.split()
                if len(parts) < 5:
                    continue
                state = parts[0].upper()
                if state != "ESTAB":
                    continue
                local = parts[3]
                remote = parts[4]
                peername = ""
                for p in parts:
                    if p.startswith("users:("):
                        peername = p

                local_host, local_port = _split_addr_port(local)
                remote_host, remote_port = _split_addr_port(remote)
                pid, process_name = _parse_ss_peername(peername)

                is_client = local_port in proxy_ports or remote_port in proxy_ports
                if is_client:
                    result.append(dict(
                        pid=pid, process=process_name,
                        local=local_host, local_port=local_port,
                        remote=remote_host, remote_port=remote_port,
                        status=state, direction="up" if remote_port in proxy_ports else "down",
                        bytes_in=0, bytes_out=0,
                    ))
        # обогащаем трафиком из conntrack (внутри try чтобы не сломал список)
        if not is_win and result:
            try:
                ct_map = _get_conntrack_map()
                for c in result:
                    key = (c["remote"], c["remote_port"])
                    ct = ct_map.get(key)
                    if ct:
                        c["bytes_out"] = ct[0]
                        c["bytes_in"] = ct[1]
            except Exception:
                pass
    except Exception:
        pass
    return result


def close_connection(remote_host, remote_port, local_port=None):
    """Закрывает TCP-соединение с указанным удалённым хостом:портом.
    Linux: tcpkill или ss -K. Windows: RST через TCP_KILL."""
    import os
    import subprocess

    is_win = os.name == "nt"
    try:
        if is_win:
            # Находим соединение и завершаем процесс-владелец
            conns = list_active_connections()
            for c in conns:
                if c["remote"] == remote_host and c["remote_port"] == remote_port:
                    if c.get("pid") and c["pid"] > 0:
                        subprocess.run(
                            ["taskkill", "/F", "/PID", str(c["pid"])],
                            capture_output=True, timeout=5,
                        )
                        return True
        else:
            # Linux: ss -K (kill)
            filter_expr = f"( dst {remote_host} and dport {remote_port} )"
            r = subprocess.run(
                ["ss", "-K", filter_expr],
                capture_output=True, timeout=5,
            )
            if r.returncode == 0:
                return True
            # fallback: tcpkill
            r = subprocess.run(
                ["tcpkill", "-9", f"host {remote_host} and port {remote_port}"],
                capture_output=True, timeout=5,
            )
            return r.returncode == 0
    except Exception:
        pass
    return False


def flush_all_connections():
    """Закрывает все ESTABLISHED соединения через прокси-порты.
    Возвращает количество закрытых соединений."""
    conns = list_active_connections()
    killed = 0
    for c in conns:
        try:
            if c.get("pid") and c["pid"] > 0 and c.get("process") != "xray":
                import os
                import signal
                if os.name == "nt":
                    import subprocess
                    subprocess.run(
                        ["taskkill", "/F", "/PID", str(c["pid"])],
                        capture_output=True, timeout=3,
                    )
                else:
                    os.kill(c["pid"], signal.SIGTERM)
                killed += 1
        except Exception:
            pass
    return killed


def _win_pid_map() -> dict[int, str]:
    """Возвращает {pid: process_name} для всех процессов Windows."""
    import subprocess
    m = {}
    try:
        r = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.splitlines():
            line = line.strip().strip('"')
            parts = line.split('","')
            if len(parts) >= 2:
                name = parts[0].strip('"')
                pid_str = parts[1].strip().strip('"') if len(parts) > 1 else ""
                if pid_str.isdigit():
                    m[int(pid_str)] = name
    except Exception:
        pass
    return m


def _split_addr_port(addr: str) -> tuple:
    """Разделяет '127.0.0.1:1080' на ('127.0.0.1', 1080).
    Убирает ::ffff: префикс (IPv4-mapped IPv6)."""
    if not addr:
        return ("", 0)
    if addr.startswith("["):
        # IPv6: [::1]:1080
        try:
            host, port = addr.rsplit("]:", 1)
            host = host.lstrip("[")
            if host.startswith("::ffff:"):
                host = host[7:]
            return (host, int(port))
        except Exception:
            return (addr, 0)
    try:
        host, port = addr.rsplit(":", 1)
        if host.startswith("::ffff:"):
            host = host[7:]
        return (host, int(port) if port.isdigit() else 0)
    except Exception:
        return (addr, 0)


def _parse_ss_peername(peername: str) -> tuple:
    """Парсит 'users:((\"chrome\",pid=1234,fd=42))' в (1234, 'chrome')."""
    if not peername:
        return (0, "")
    try:
        import re
        m = re.search(r'"([^"]+)".*?pid=(\d+)', peername)
        if m:
            return (int(m.group(2)), m.group(1))
    except Exception:
        pass
    return (0, "")



