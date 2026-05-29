"""Общение с Xray API: статус, управление outbound, горячая замена.

Использует утилиту командной строки Xray (xray api ...) через subprocess.
"""

import json
import os
import re
import subprocess
import tempfile

from .db import xray_bin
from .utils import add_log
from config import API_LISTEN, API_PORT


def xray_api_ok():
    """Проверяет, отвечает ли Xray API."""
    try:
        r = subprocess.run(
            [xray_bin(), "api", "statsquery", "-s", f"{API_LISTEN}:{API_PORT}"],
            capture_output=True,
            timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def list_active_outbounds():
    """Возвращает список тегов активных outbound через Xray API statsquery."""
    try:
        r = subprocess.run(
            [xray_bin(), "api", "statsquery", "-s", f"{API_LISTEN}:{API_PORT}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode != 0:
            return []
        tags = set()
        for line in r.stdout.splitlines():
            m = re.search(r"outbound>>>([^>]+)>>>traffic>>>([a-z]+)", line)
            if m:
                tags.add(m.group(1))
        return sorted(tags)
    except Exception:
        return []


def remove_all_outbounds():
    """Удаляет все node* outbound из Xray через API."""
    for tag in list_active_outbounds():
        if tag.startswith("node"):
            try:
                subprocess.run(
                    [
                        xray_bin(),
                        "api",
                        "removeoutbound",
                        "-s",
                        f"{API_LISTEN}:{API_PORT}",
                        "--tag",
                        tag,
                    ],
                    capture_output=True,
                    timeout=10,
                )
            except Exception:
                pass


def add_outbound(ob):
    """Добавляет один outbound в Xray через API (через временный JSON-файл)."""
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    with tmp:
        json.dump({"outbound": ob}, tmp)
        tmp_path = tmp.name
    try:
        subprocess.run(
            [
                xray_bin(),
                "api",
                "addoutbound",
                "-s",
                f"{API_LISTEN}:{API_PORT}",
                tmp_path,
            ],
            capture_output=True,
            timeout=10,
        )
    except Exception:
        pass
    finally:
        os.unlink(tmp_path)


def _systemctl_restart_xray():
    """Перезапускает systemd-сервис xray. Использует sudo, если не root."""
    cmd = ["systemctl", "restart", "xray"]
    try:
        if os.geteuid() != 0:
            cmd.insert(0, "sudo")
    except AttributeError:
        pass
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=15)
        if r.returncode == 0:
            add_log("INFO", "systemd xray restarted")
            return True
        add_log("WARN", f"systemctl restart xray failed: {r.stderr.decode()[:200]}")
    except Exception as e:
        add_log("WARN", f"Could not restart systemd xray: {e}")
    return False
