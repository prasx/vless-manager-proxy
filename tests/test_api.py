"""Смоук-тесты API: прогресс, настройки, рекомендации по производительности.

Запуск: python -m unittest discover -s tests -v

Работают с временным файлом БД и test client'ом Flask: реальные данные
и Xray не затрагиваются.
"""

import tempfile
import threading
import unittest
from pathlib import Path

import app.db as app_db
from app import create_app
from app.db import Settings, init_db


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
        for field_id in ("checkBatchSize", "tcpPrefilter", "speedStageBudget", "profileMaxAgeMin"):
            self.assertIn(f'id="{field_id}"', html)
        self.assertNotIn('id="maxWorkers"', html)

        sources_html = self.client.get("/sources").get_data(as_text=True)
        for element_id in ("btnRefreshStale", "configPreview"):
            self.assertIn(f'id="{element_id}"', sources_html)

        dash_html = self.client.get("/").get_data(as_text=True)
        self.assertIn('id="refreshStaleBtn"', dash_html)


if __name__ == "__main__":
    unittest.main()
