"""Утилиты: работа со временем, логирование, гео-определение страны."""

import json
import threading
import traceback
from datetime import datetime
from zoneinfo import ZoneInfo
from typing import Optional

from .db import _get_conn, Settings
from config import MOSCOW_TZ, UTC_TZ

_geo_cache: dict[str, str] = {}
_geo_cache_lock = threading.Lock()

_current_cid: str = ""
_cid_lock = threading.Lock()


def set_correlation_id(cid: str) -> None:
    """Устанавливает correlation_id для всех последующих логов в этом потоке."""
    global _current_cid
    with _cid_lock:
        _current_cid = cid


def get_correlation_id() -> str:
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


def trim_logs_startup() -> None:
    """Принудительная чистка логов при старте (учитывает настройки)."""
    _trim_logs()


# ─── Определение страны ───


def detect_country(host):
    """Определяет страну по IP хоста через ip-api.com (с кешированием)."""
    with _geo_cache_lock:
        if host in _geo_cache:
            return _geo_cache[host]
    try:
        import socket
        import urllib.request

        ip = socket.gethostbyname(host)
        url = f"http://ip-api.com/json/{ip}?fields=countryCode"
        with urllib.request.urlopen(url, timeout=3) as r:
            data = json.loads(r.read().decode())
        cc = data.get("countryCode", "")
        if cc:
            with _geo_cache_lock:
                _geo_cache[host] = cc
            return cc
    except Exception:
        pass
    add_log("WARN", f"Failed to detect country for {host}")
    return ""


def enrich_country(pid, host):
    """Обновляет страну для прокси по его ID."""
    from .db import db_q

    cc = detect_country(host)
    if cc:
        db_q("UPDATE proxies SET country=? WHERE id=?", (cc, pid))
        return True
    return False


_enrich_lock = threading.Lock()

def count_active_connections(ports: list[int]) -> dict[int, int]:
    """Подсчитывает активные TCP-соединения на указанных портах (через netstat/ss)."""
    result = {p: 0 for p in ports}
    try:
        conns = list_active_connections(ports)
        for c in conns:
            lp = c.get("local_port")
            if lp in ports:
                result[lp] = result.get(lp, 0) + 1
    except Exception:
        pass
    return result


def _get_conntrack_map():
    """Парсит conntrack, возвращает {(client_ip, client_port): (bytes_to_client, bytes_from_client)}.
    Тихий возврат {} если conntrack недоступен."""
    import re
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

    for line in lines:
        if "dport=1080" not in line and "dport=1081" not in line:
            continue
        vals = re.findall(r'bytes=(\d+)', line)
        if len(vals) < 2:
            continue
        m = re.search(r'src=([^\s]+)\s+.*?sport=(\d+)\s+dport=108[01]', line)
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


def list_active_connections(proxy_ports: list[int] = (1080, 1081)) -> list[dict]:
    """Возвращает детальный список TCP-соединений через прокси-порты.
    Каждый элемент: {pid, process, local, local_port, remote, remote_port, status, direction, bytes_in, bytes_out}"""
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
            from config import API_LISTEN
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


def enrich_all_unknown_countries():
    """Заполняет страну для всех прокси, у которых она отсутствует или невалидна.
    Предотвращает конкурентный запуск через threading.Lock()."""
    if not _enrich_lock.acquire(blocking=False):
        return
    try:
        from .db import db_q

        rows = db_q(
            "SELECT id, host FROM proxies WHERE country IS NULL OR country = '' OR length(country) > 2"
        )
        enriched = 0
        for r in rows:
            if enrich_country(r["id"], r["host"]):
                enriched += 1
        if enriched:
            add_log("INFO", f"Enriched country for {enriched} proxies")
    finally:
        _enrich_lock.release()
