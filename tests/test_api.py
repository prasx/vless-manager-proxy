"""Смоук-тесты API: прогресс, настройки, рекомендации по производительности.

Запуск: python -m unittest discover -s tests -v

Работают с временным файлом БД и test client'ом Flask: реальные данные
и Xray не затрагиваются.
"""

from html.parser import HTMLParser
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import app.db as app_db
from app import create_app
from app.db import Settings, init_db


class _AncestorTracker(HTMLParser):
    """Запоминает классы предков для элементов с id (проверка структуры)."""

    def __init__(self):
        super().__init__()
        self.stack: list[tuple[str, str]] = []
        self.parents: dict[str, list[str]] = {}

    def handle_starttag(self, tag, attrs):
        data = dict(attrs)
        if data.get("id"):
            self.parents[data["id"]] = [cls for _tag, cls in self.stack]
        self.stack.append((tag, data.get("class", "")))

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                return


class ApiTestCase(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self._old_db = app_db.DATABASE
        app_db.DATABASE = Path(self._tmpdir.name) / "test.db"
        app_db._tls = threading.local()
        Settings.invalidate()
        init_db()
        self.app = create_app()
        self.client = self.app.test_client()

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


class TestApiSmoke(ApiTestCase):
    def test_status_empty_db(self):
        r = self.client.get("/api/status")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["total"], 0)
        self.assertEqual(data["working"], 0)

    def test_profile_test_accepts_speed_url_override(self):
        """Ручной тест профиля может проверить конкретный файл замера."""
        from app.utils import now_utc

        app_db.db_q(
            "INSERT INTO proxies (link, host, port, status, added_at) VALUES (?,?,?,?,?)",
            (
                "vless://11111111-2222-3333-4444-555555555555@ok.test:443",
                "ok.test", 443, "working", now_utc(),
            ),
        )
        pid = app_db.db_q("SELECT id FROM proxies ORDER BY id DESC LIMIT 1")[0]["id"]
        fake = {
            "busy": False, "status": "working", "latency": 42,
            "speed": 0, "speed_max": 0, "speed_url": "http://mirror.test/10mb",
            "speed_error": "failed to read response: connection reset",
            "error": None,
        }
        with mock.patch(
            "app.routes.api.proxy_manager.measure_single", return_value=fake
        ) as measure:
            r = self.client.post(
                f"/api/test/{pid}", json={"speed_url": "http://mirror.test/10mb"}
            )
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("connection reset", data["speed_error"])
        measure.assert_called_once_with(pid, speed_url="http://mirror.test/10mb")

    def test_progress_payload_has_stages(self):
        r = self.client.get("/api/test-progress")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        for key in ("running", "phase", "stages", "total", "done", "ok"):
            self.assertIn(key, data)

    def test_performance_recommendations(self):
        from app.utils import now_utc

        app_db.db_q(
            "INSERT INTO proxies (link, host, port, status, added_at) VALUES (?,?,?,?,?)",
            ("vless://u@ok.test:443", "ok.test", 443, "pending", now_utc()),
        )
        r = self.client.get("/api/performance/recommendations")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["due"], 1)
        self.assertIn("check_batch_size", data["current"])
        self.assertIn("estimated_seconds", data["current"])
        self.assertGreater(len(data["targets"]), 0)
        self.assertIn("last_stages", data)

    def test_settings_roundtrip_and_validation(self):
        r = self.client.post(
            "/api/settings",
            json={"check_batch_size": "64", "tcp_prefilter_timeout": "1.5"},
        )
        self.assertEqual(r.status_code, 200, r.get_json())
        Settings.invalidate()
        self.assertEqual(Settings.check_batch_size(), 64)
        self.assertEqual(Settings.tcp_prefilter_timeout(), 1.5)

        bad = self.client.post("/api/settings", json={"probe_timeout": "0"})
        self.assertEqual(bad.status_code, 400)

        bad_float = self.client.post(
            "/api/settings", json={"tcp_prefilter_timeout": "99"}
        )
        self.assertEqual(bad_float.status_code, 400)

    def test_due_filter_excludes_backoff(self):
        from app.utils import now_utc

        app_db.db_q(
            "INSERT INTO proxies (link, host, port, status, added_at, next_test_at) "
            "VALUES (?,?,?,?,?, datetime('now', '+3600 seconds'))",
            ("vless://u@wait.test:443", "wait.test", 443, "failed", now_utc()),
        )
        data = self.client.get("/api/performance/recommendations").get_json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["due"], 0, "профиль в backoff не должен попадать в прогон")


    def test_config_preview_reports_selection(self):
        from app.utils import now_utc

        app_db.db_q(
            "INSERT INTO proxies (link, host, port, status, added_at, last_test_at, "
            "latency_vless, speed_kbps, country) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                "vless://11111111-1111-1111-1111-111111111111@ok.test:443?security=tls&type=tcp#US",
                "ok.test", 443, "working", now_utc(), now_utc(), 120, 8000, "US",
            ),
        )
        r = self.client.get("/api/config/preview")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["counts"]["working_total"], 1)
        self.assertEqual(len(data["selected"]), 1)
        self.assertEqual(data["selected"][0]["tier"], 1)  # замерен
        self.assertIn("profile_fresh_minutes", data["settings"])

    def test_sources_endpoint_includes_quality(self):
        from app.utils import now_utc

        app_db.db_q(
            "INSERT INTO sources (name, url, type, created_at, last_status) VALUES (?,?,?,?,?)",
            ("src", "https://example.test/sub.txt", "url", now_utc(), "ok"),
        )
        r = self.client.get("/api/sources")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(len(data), 1)
        self.assertIn("score", data[0])
        self.assertIn("verdict", data[0])

    def test_refresh_stale_without_targets(self):
        r = self.client.post("/api/refresh-stale")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertFalse(data["success"])
        self.assertEqual(data["queued"], 0)

    def test_diagnose_reports_counts(self):
        data = self.client.get("/api/import/diagnose").get_json()
        self.assertEqual(data["total"], 0)
        self.assertEqual(data["checked"], 0)
        self.assertEqual(data["skipped"], 0)
        self.assertEqual(data["reports"], [])

    def test_countries_reports_no_country(self):
        """Фильтр стран не покрывает профили без страны, и API это говорит."""
        from app.utils import now_utc

        for host, country in (("one.test", ""), ("two.test", "US")):
            app_db.db_q(
                "INSERT INTO proxies (link, host, port, country, status, added_at) VALUES (?,?,?,?,?,?)",
                (f"vless://11111111-1111-1111-1111-111111111111@{host}:443", host, 443, country, "working", now_utc()),
            )
        data = self.client.get("/api/countries").get_json()
        self.assertEqual(data["no_country"], 1)
        self.assertEqual([c["code"] for c in data["countries"]], ["US"])

    def test_pages_render(self):
        for path in ("/", "/logs", "/sources", "/settings"):
            r = self.client.get(path)
            self.assertEqual(r.status_code, 200, f"{path} не отрендерился")
        html = self.client.get("/settings").get_data(as_text=True)
        for field_id in ("checkBatchSize", "tcpPrefilter", "speedStageBudget", "profileMaxAgeMin",
                         "probeRetries", "tcpPrefilterRetries", "probeUrlTestBtn",
                         "socksPort", "httpPort", "apiPort", "tcpPrefilterWorkers"):
            self.assertIn(f'id="{field_id}"', html)
        self.assertNotIn('id="maxWorkers"', html)

        sources_html = self.client.get("/sources").get_data(as_text=True)
        for element_id in ("btnRefreshStale", "configPreview"):
            self.assertIn(f'id="{element_id}"', sources_html)

        dash_html = self.client.get("/").get_data(as_text=True)
        self.assertIn('id="refreshStaleBtn"', dash_html)

    # ─── Тест лучших URL для проверок ───

    def test_pagination_bar_is_reachable(self):
        """Регрессия: пагинация управляется атрибутом hidden, а не style.display.

        В style.css есть `[hidden] { display: none !important; }`. Когда JS
        выставлял `bar.style.display = 'flex'`, `!important` оставлял панель
        скрытой — кнопки «Показать ещё» не было в списке прокси и логов.
        """
        root = Path(__file__).resolve().parent.parent
        css = (root / "static/style.css").read_text(encoding="utf-8")
        self.assertIn("[hidden]", css)
        self.assertIn("display: none !important", css)

        for name, _bar_id in (("dashboard.js", "paginationBar"), ("logs.js", "logPagination")):
            js = (root / "static" / name).read_text(encoding="utf-8")
            start = js.index("function updatePagination")
            block = js[start:start + 1200]
            self.assertIn("bar.hidden", block, f"{name}: пагинация должна менять hidden")
            self.assertNotIn(
                "bar.style.display", block,
                f"{name}: style.display не перебивает [hidden] !important",
            )

        for path, bar_id in (("/", "paginationBar"), ("/logs", "logPagination")):
            html = self.client.get(path).get_data(as_text=True)
            self.assertIn(f'id="{bar_id}"', html)
            # Кнопка существует и привязана к загрузке следующей страницы.
            self.assertIn("showMoreBtn" if path == "/" else "logShowMoreBtn", html)

        dash = (root / "static/dashboard.js").read_text(encoding="utf-8")
        self.assertIn("offset", dash)
        self.assertIn("totalCount", dash)

    def test_urls_candidates(self):
        r = self.client.get("/api/urls/candidates")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("current", data["probe"])
        self.assertIn("candidates", data["probe"])
        self.assertGreaterEqual(len(data["probe"]["candidates"]), 3)
        self.assertIn("current", data["speed"])
        self.assertIn("auto", data)

    def test_settings_sections_are_flat_and_present(self):
        """Настройки — плоский список секций без вкладок, в логичном порядке."""
        html = self.client.get("/settings").get_data(as_text=True)
        tracker = _AncestorTracker()
        tracker.feed(html)
        expected = [
            "sec-xray", "sec-network", "sec-sniffing", "sec-geo", "sec-balancer",
            "sec-filter", "sec-probe", "sec-check", "sec-perf", "sec-speed",
            "sec-schedule", "sec-system",
        ]
        for section_id in expected:
            self.assertIn(section_id, tracker.parents, f"нет секции {section_id}")
        # Вкладок больше нет: ни кнопок role=tab, ни панелей.
        self.assertNotIn('role="tablist"', html)
        self.assertNotIn("settings-tabpanel", html)
        self.assertNotIn('id="settingsTabs"', html)
        # Порядок секций в документе соответствует логике страницы.
        positions = [html.index(f'id="{sid}"') for sid in expected]
        self.assertEqual(positions, sorted(positions), "секции должны идти по порядку")

    def test_url_test_result_outside_flex_row(self):
        """Блок результата «Тест URL» — не flex-элемент внутри .tuning-item.

        Внутри flex-строки он сжимался в колонку по несколько символов и
        разъезжался по строкам — именно это выглядело «ужасно».
        """
        html = self.client.get("/settings").get_data(as_text=True)
        tracker = _AncestorTracker()
        tracker.feed(html)
        for element_id in ("probeUrlTestResult", "speedUrlTestResult"):
            self.assertIn(element_id, tracker.parents, f"{element_id} нет на странице")
            ancestors = tracker.parents[element_id]
            self.assertFalse(
                any("tuning-item" in cls for cls in ancestors),
                f"{element_id} не должен быть внутри .tuning-item: {ancestors}",
            )
            self.assertTrue(
                any(("tuning-section" in cls or "tuning-group" in cls) for cls in ancestors),
                f"{element_id} должен жить в секции настроек: {ancestors}",
            )

    def test_urls_test_applies_best(self):
        from app import netcheck

        report = {
            "kind": "probe",
            "current": "http://dead.test/204",
            "best": "http://alive.test/204",
            "applied": "http://alive.test/204",
            "results": [
                {"url": "http://alive.test/204", "ok": True, "status": 204, "ms": 30},
                {"url": "http://dead.test/204", "ok": False, "status": 0, "ms": 4000},
            ],
        }
        with mock.patch.object(netcheck, "test_and_apply", return_value=report) as fn, \
                mock.patch("app.routes.api.xray_configurator.apply_all"):
            r = self.client.post("/api/urls/test", json={"kind": "probe", "apply": True})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["best"], "http://alive.test/204")
        self.assertEqual(data["applied"], "http://alive.test/204")
        fn.assert_called_once()

    def test_urls_test_all_kinds(self):
        from app import netcheck

        def fake_apply(kind, urls=None, timeout=6.0, apply=True):
            return {"kind": kind, "current": "", "best": f"http://{kind}.test",
                    "applied": f"http://{kind}.test", "results": []}

        with mock.patch.object(netcheck, "test_and_apply", side_effect=fake_apply) as fn, \
                mock.patch("app.routes.api.xray_configurator.apply_all"):
            data = self.client.post("/api/urls/test", json={"kind": "all"}).get_json()
        self.assertIn("probe", data)
        self.assertIn("speed", data)
        self.assertEqual(fn.call_count, 2)

    def test_speedtest_direct_route(self):
        fake = {
            "ok": True, "avg_kbps": 12000, "max_kbps": 18000,
            "bytes": 1500000, "elapsed": 10.0, "url": "http://x.test/10mb",
        }
        with mock.patch(
            "app.routes.api.proxy_manager.speedtest_direct", return_value=fake
        ) as fn:
            r = self.client.post(
                "/api/speedtest/direct",
                json={"url": "http://x.test/10mb", "window": 10},
            )
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(r.get_json()["avg_kbps"], 12000)
        fn.assert_called_once_with("http://x.test/10mb", 10)

    def test_ports_settings_roundtrip_and_validation(self):
        r = self.client.post(
            "/api/settings",
            json={"socks_port": "11080", "http_port": "11081", "api_port": "11085"},
        )
        self.assertEqual(r.status_code, 200, r.get_json())
        Settings.invalidate()
        self.assertEqual(Settings.socks_port(), 11080)
        self.assertEqual(Settings.http_port(), 11081)
        self.assertEqual(Settings.api_port(), 11085)

        # Порт вне диапазона и дубликаты портов отклоняются.
        self.assertEqual(
            self.client.post("/api/settings", json={"socks_port": "0"}).status_code, 400
        )
        self.assertEqual(
            self.client.post("/api/settings", json={"socks_port": "11081"}).status_code,
            400,
            "порт не должен совпадать с HTTP-портом",
        )

    def test_batch_size_default_is_128(self):
        Settings.invalidate()
        self.assertEqual(Settings.check_batch_size(), 128)
        self.assertEqual(Settings.tcp_prefilter_workers(), 128)

    def test_settings_accepts_new_tuning_fields(self):
        r = self.client.post(
            "/api/settings",
            json={
                "probe_retries": "2",
                "tcp_prefilter_retries": "0",
                "probe_timeout": "10",
                "tcp_prefilter_timeout": "4",
            },
        )
        self.assertEqual(r.status_code, 200, r.get_json())
        Settings.invalidate()
        self.assertEqual(Settings.probe_retries(), 2)
        self.assertEqual(Settings.tcp_prefilter_retries(), 0)
        self.assertEqual(Settings.probe_timeout(), 10)
        self.assertEqual(Settings.tcp_prefilter_timeout(), 4.0)

        bad = self.client.post("/api/settings", json={"probe_retries": "9"})
        self.assertEqual(bad.status_code, 400)
        bad = self.client.post("/api/settings", json={"tcp_prefilter_timeout": "99"})
        self.assertEqual(bad.status_code, 400)


if __name__ == "__main__":
    unittest.main()
