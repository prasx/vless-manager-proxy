"""Тесты подбора URL проверки, разбора «грязных» ссылок и починки Xray API.

Запуск: python -m unittest discover -s tests -v

Сеть не нужна: HTTP-ответы подменяются, БД — временный файл.
"""

import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import app.db as app_db
from app import netcheck
from app.checker import ProbeUrlStats, probe_median, probe_once
from app.db import Settings, init_db
from app.importer import _split_vless_lines
from app.vless import normalize_network, normalize_security, parse_vless


# ─── Вспомогательный HTTP-прокси с настраиваемым ответом ───


class StatusServer(threading.Thread):
    """Локальный http-inbound фейкового чекера: отвечает заданным статусом."""

    def __init__(self, status: int, body: bytes = b""):
        super().__init__(daemon=True)
        self.status = status
        self.body = body
        self._stop = threading.Event()
        self._srv = None
        self.port = 0

    def run(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        srv.settimeout(0.2)
        self.port = srv.getsockname()[1]
        self._srv = srv
        while not self._stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
        try:
            srv.close()
        except OSError:
            pass

    def _handle(self, conn):
        try:
            conn.settimeout(2)
            try:
                conn.recv(65536)
            except OSError:
                return
            body = self.body
            conn.sendall(
                f"HTTP/1.1 {self.status} Status\r\n"
                f"Content-Length: {len(body)}\r\n\r\n".encode() + body
            )
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self._stop.set()
        try:
            if self._srv:
                self._srv.close()
        except OSError:
            pass


class TempDBTestCase(unittest.TestCase):
    """Подменяет файл БД на временный: реальный proxies.db не трогаем."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self._old_db = app_db.DATABASE
        app_db.DATABASE = Path(self._tmpdir.name) / "test.db"
        app_db._tls = threading.local()
        Settings.invalidate()
        init_db()

    def tearDown(self):
        # Сбрасываем буфер логов, пока активна временная БД: иначе отложенный
        # таймер запишет логи в реальную proxies.db уже после подмены.
        from app.utils import flush_logs_now

        flush_logs_now()
        conn = getattr(app_db._tls, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        app_db._tls = threading.local()
        app_db.DATABASE = self._old_db
        Settings.invalidate()
        self._tmpdir.cleanup()


# ─── Разбор ссылок ───


class TestLinkSanitize(unittest.TestCase):
    def test_raw_and_httpupgrade_alias(self):
        self.assertEqual(normalize_network("raw"), "tcp")
        self.assertEqual(normalize_network("httpupgrade"), "httpupgrade")
        self.assertEqual(normalize_network("splithttp"), "xhttp")

    def test_junk_glued_to_transport(self):
        """Ремарка следующей ссылки, приклеенная к type, не ломает узел."""
        self.assertEqual(normalize_network("tcp#5🐲@oneclickvpnkeys"), "tcp")
        self.assertEqual(normalize_network("tcp¬e=volt____network"), "tcp")

    def test_security_aliases(self):
        self.assertEqual(normalize_security("false"), "none")
        self.assertEqual(normalize_security(""), "none")
        self.assertEqual(normalize_security("xtls"), "tls")

    def test_html_entities_in_reality_link(self):
        link = (
            "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443"
            "?security=reality&amp;pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "&amp;sid=ab12&amp;type=tcp&amp;sni=www.example.com#DE"
        )
        parsed = parse_vless(link)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["security"], "reality")
        self.assertEqual(parsed["pbk"], "A" * 43)
        self.assertEqual(parsed["type"], "tcp")
        self.assertEqual(parsed["sni"], "www.example.com")

    def test_type_raw_builds_tcp(self):
        link = (
            "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443"
            "?type=raw&security=tls&sni=example.com"
        )
        parsed = parse_vless(link)
        self.assertEqual(parsed["type"], "tcp")

    def test_glued_links_are_split(self):
        content = (
            "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?type=tcp#a"
            "vless://66666666-7777-8888-9999-000000000000@5.6.7.8:8443?type=ws#b"
        )
        links = _split_vless_lines(content)
        self.assertEqual(len(links), 2)

    def test_html_page_and_amp_entities(self):
        page = (
            "<html><body><p>config:</p>"
            '<a href="vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443'
            '?security=reality&amp;pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
            '&amp;type=tcp#DE">node</a>'
            "</body></html>"
        )
        links = _split_vless_lines(page)
        self.assertEqual(len(links), 1)
        self.assertNotIn("&amp;", links[0])
        self.assertIsNotNone(parse_vless(links[0]))

    def test_base64_subscription(self):
        import base64

        raw = (
            "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?type=tcp#DE\n"
            "vless://66666666-7777-8888-9999-000000000000@5.6.7.8:443?type=ws#US\n"
        )
        encoded = base64.b64encode(raw.encode()).decode()
        links = _split_vless_lines(encoded)
        self.assertEqual(len(links), 2)


# ─── Статистика URL пробы ───


class TestProbeUrlStats(unittest.TestCase):
    def test_orders_by_success_and_picks_best(self):
        stats = ProbeUrlStats(["http://a", "http://b", "http://c"])
        for _ in range(5):
            stats.record("http://a", False, "timeout")
            stats.record("http://b", True)
        stats.record("http://c", True)
        ordered = stats.ordered()
        self.assertEqual(ordered[0], "http://b")
        self.assertEqual(stats.best(), "http://b")
        self.assertEqual(stats.ok_count("http://b"), 5)
        self.assertIn("http://b", stats.summary())
        self.assertGreater(stats.total(), 0)

    def test_best_empty_without_success(self):
        stats = ProbeUrlStats(["http://a"])
        stats.record("http://a", False, "timeout")
        self.assertEqual(stats.best(), "")


class TestProbeMedianFallback(unittest.TestCase):
    def test_falls_back_to_second_url(self):
        calls = []

        def fake_probe_once(port, timeout, url):
            calls.append((url, timeout))
            if url == "http://dead":
                return False, 0, "timeout", timeout
            return True, 42, "", 0.01

        with mock.patch("app.checker.probe_once", side_effect=fake_probe_once), \
                mock.patch.object(Settings, "probe_retries", classmethod(lambda cls: 1)):
            stats = ProbeUrlStats(["http://dead", "http://alive"])
            ok, lat, err, samples = probe_median(
                1, 1.0, ["http://dead", "http://alive"], samples=1, stats=stats
            )
        self.assertTrue(ok, err)
        self.assertEqual(lat, 42)
        self.assertEqual([c[0] for c in calls], ["http://dead", "http://alive"])
        self.assertEqual(stats.ok_count("http://alive"), 1)
        self.assertEqual(stats.best(), "http://alive")


class TestProbeAcceptsAnyHttpResponse(unittest.TestCase):
    """HTTP 403 — это ответ, значит туннель работает (раньше был «http 403»)."""

    def test_403_is_alive(self):
        srv = StatusServer(403)
        srv.start()
        try:
            for _ in range(50):
                if srv.port:
                    break
                threading.Event().wait(0.02)
            ok, lat, err, _ = probe_once(srv.port, 1.0, "http://probe.local/x")
        finally:
            srv.stop()
        self.assertTrue(ok, err)
        self.assertGreaterEqual(lat, 1)

    def test_503_with_xray_dial_error_is_dead(self):
        """Xray отвечает 503 с текстом dial-ошибки — туннель на самом деле мёртв."""
        srv = StatusServer(
            503, body=b"failed to dial mirror.test:80: i/o timeout"
        )
        srv.start()
        try:
            for _ in range(50):
                if srv.port:
                    break
                threading.Event().wait(0.02)
            ok, _lat, err, _ = probe_once(srv.port, 1.0, "http://probe.local/x")
        finally:
            srv.stop()
        self.assertFalse(ok, "dial-ошибка Xray не должна считаться живым профилем")
        self.assertIn("proxy dial failed", err)

    def test_target_503_without_dial_text_is_alive(self):
        """503 самого сайта (обслуживание) — это ответ, туннель жив."""
        srv = StatusServer(503, body=b"<html>maintenance</html>")
        srv.start()
        try:
            for _ in range(50):
                if srv.port:
                    break
                threading.Event().wait(0.02)
            ok, _lat, err, _ = probe_once(srv.port, 1.0, "http://probe.local/x")
        finally:
            srv.stop()
        self.assertTrue(ok, err)


# ─── Тест/подбор URL проверки ───


class TestUrlSelection(TempDBTestCase):
    def test_speed_catalog_has_http_fallbacks(self):
        """Запасные URL замера должны включать plain HTTP: TLS/CONNECT у exit-нод
        может не работать, а замеру скорости HTTPS не нужен."""
        http_urls = [
            u for u in netcheck.SPEED_URL_CANDIDATES if u.startswith("http://")
        ]
        self.assertGreaterEqual(len(http_urls), 3)
        self.assertTrue(
            any("tele2" in u or "bit.nl" in u or "ovh" in u for u in http_urls)
        )
        self.assertEqual(netcheck.DEFAULT_SPEED_URL, netcheck.SPEED_URL_CANDIDATES[0])

    def test_probe_url_candidates_current_first_and_capped(self):
        Settings.set("probe_url", "http://my.test/generate_204")
        urls = netcheck.probe_url_candidates()
        self.assertEqual(urls[0], "http://my.test/generate_204")
        self.assertLessEqual(len(urls), netcheck.MAX_PROBE_CANDIDATES)
        self.assertIn("http://cp.cloudflare.com/generate_204", urls)

    def test_custom_catalog_from_settings(self):
        Settings.set("probe_url_candidates", "http://one.test/204\nhttp://two.test/204")
        self.assertEqual(
            netcheck.probe_url_catalog(), ["http://one.test/204", "http://two.test/204"]
        )

    def test_test_and_apply_picks_best(self):
        Settings.set("probe_url", "http://dead.test/204")

        def fake_test(url, timeout=6.0):
            if "dead" in url:
                return {"url": url, "ok": False, "status": 0, "ms": 5000, "error": "timeout"}
            return {"url": url, "ok": True, "status": 204, "ms": 50, "error": ""}

        with mock.patch("app.netcheck.test_probe_url", side_effect=fake_test):
            report = netcheck.test_and_apply(
                "probe", ["http://dead.test/204", "http://alive.test/204"], apply=True
            )
        self.assertEqual(report["best"], "http://alive.test/204")
        self.assertEqual(report["applied"], "http://alive.test/204")
        Settings.invalidate()
        self.assertEqual(Settings.probe_url(), "http://alive.test/204")

    def test_ensure_probe_url_switches_dead_url(self):
        Settings.set("probe_url", "http://dead.test/204")
        Settings.set("probe_url_candidates", "http://alive.test/204")

        def fake_test(url, timeout=6.0):
            if "dead" in url:
                return {"url": url, "ok": False, "status": 0, "ms": 5000, "error": "timeout"}
            return {"url": url, "ok": True, "status": 204, "ms": 40, "error": ""}

        with mock.patch("app.netcheck.test_probe_url", side_effect=fake_test):
            chosen = netcheck.ensure_probe_url(timeout=2)
        self.assertEqual(chosen, "http://alive.test/204")
        Settings.invalidate()
        self.assertEqual(Settings.probe_url(), "http://alive.test/204")

    def test_ensure_probe_url_keeps_current_when_all_dead(self):
        Settings.set("probe_url", "http://only.test/204")

        def fake_test(url, timeout=6.0):
            return {"url": url, "ok": False, "status": 0, "ms": 3000, "error": "timeout"}

        with mock.patch("app.netcheck.test_probe_url", side_effect=fake_test):
            chosen = netcheck.ensure_probe_url(timeout=1)
        self.assertEqual(chosen, "http://only.test/204")

    def test_auto_select_disabled(self):
        Settings.set("probe_url_auto", "false")
        Settings.set("probe_url", "http://keep.test/204")
        with mock.patch("app.netcheck.test_probe_url") as test:
            self.assertEqual(netcheck.ensure_probe_url(), "http://keep.test/204")
        test.assert_not_called()


# ─── Миграции ───


class TestMigrations(unittest.TestCase):
    """Старые дефолты переводятся на новые URL/таймауты/пачку проверки."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self._old_db = app_db.DATABASE
        app_db.DATABASE = Path(self._tmpdir.name) / "test.db"
        app_db._tls = threading.local()
        app_db._get_conn().close()
        # Готовим «старую» БД: схема есть, миграции до v5 применены.
        conn = app_db._get_conn()
        app_db._ensure_schema(conn)
        settings = {
            "schema_version": "5",
            "probe_url": "https://www.gstatic.com/generate_204",
            "speed_test_url": "https://ftp.bit.nl/speedtest/10mb.bin",
            "probe_timeout": "5",
            "tcp_prefilter_timeout": "2",
            "speed_stage_budget_sec": "120",
            "check_batch_size": "64",
        }
        for k, v in settings.items():
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, v)
            )
        conn.commit()
        conn.close()
        Settings.invalidate()
        init_db()
        Settings.invalidate()

    def tearDown(self):
        # Сбрасываем буфер логов, пока активна временная БД: иначе отложенный
        # таймер запишет логи в реальную proxies.db уже после подмены.
        from app.utils import flush_logs_now

        flush_logs_now()
        conn = getattr(app_db._tls, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        app_db._tls = threading.local()
        app_db.DATABASE = self._old_db
        Settings.invalidate()
        self._tmpdir.cleanup()

    def test_migrates_urls_and_timeouts(self):
        self.assertEqual(Settings.probe_url(), "http://cp.cloudflare.com/generate_204")
        self.assertEqual(
            Settings.get("speed_test_url"), netcheck.DEFAULT_SPEED_URL
        )
        self.assertEqual(Settings.probe_timeout(), 8)
        self.assertEqual(Settings.tcp_prefilter_timeout(), 3.0)
        self.assertEqual(Settings.speed_stage_budget_sec(), 600)
        self.assertEqual(Settings.get("schema_version"), "7")

    def test_migrates_batch_size(self):
        """Пачка 64 (прежний дефолт) переезжает на 128, кастомные — нет."""
        self.assertEqual(Settings.check_batch_size(), 128)
        self.assertEqual(Settings.tcp_prefilter_workers(), 128)

    def test_ports_defaults(self):
        self.assertEqual(Settings.socks_port(), 1080)
        self.assertEqual(Settings.http_port(), 1081)
        self.assertEqual(Settings.api_port(), 10085)

    def test_new_settings_have_defaults(self):
        for key in ("probe_retries", "tcp_prefilter_retries", "probe_url_auto"):
            self.assertTrue(Settings.get(key), f"нет значения для {key}")
        self.assertEqual(Settings.probe_retries(), 1)
        self.assertEqual(Settings.tcp_prefilter_retries(), 1)
        self.assertTrue(Settings.probe_url_auto())
        # Пользовательское значение URL не должно перезаписываться.
        Settings.set("probe_url", "http://custom.test/204")
        Settings.invalidate()
        self.assertEqual(Settings.probe_url(), "http://custom.test/204")


if __name__ == "__main__":
    unittest.main()
