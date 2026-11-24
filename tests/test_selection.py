"""Тесты политики допуска профилей и оценки источников.

Проверяем ровно те правила, из-за которых раньше «рабочие и замеренные» сервера
не попадали в конфиг и подписку, а мёртвые — попадали:

    * замеренные профили не вытесняются незамеренными;
    * устаревший «working» не считается доказательством работоспособности;
    * при заданном пороге скорости незамеренный профиль не проходит;
    * битая ссылка не попадает ни в конфиг, ни в подписку;
    * тег outbound привязан к профилю, а не к позиции в списке;
    * у источников есть оценка и вердикт, и они идут в приоритете.

Тесты работают с временной БД и не требуют Xray и сети.
"""

import tempfile
import threading
import unittest
import uuid
from datetime import timedelta
from pathlib import Path
from unittest import mock

import app.db as app_db
import app.subscribe as app_subscribe
from app.db import Settings, db_q, init_db
from app.selection import config_rows, node_tag, retest_targets
from app.utils import now_utc


class TempDBTestCase(unittest.TestCase):
    """Подменяет файл БД на временный: рабочий proxies.db не затрагивается."""

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

    # ─── Помощники ───

    @staticmethod
    def _link(host: str, security: str = "tls", country: str = "US") -> str:
        uid = uuid.uuid4()
        return f"vless://{uid}@{host}:443?security={security}&type=tcp&sni={host}#{country}"

    def _insert(
        self,
        host: str,
        *,
        status: str = "working",
        latency: int = 100,
        speed: int = 0,
        age_min: int = 0,
        source_id=None,
        security: str = "tls",
        link: str | None = None,
        last_ok: bool = True,
    ) -> int:
        ts = (now_utc() - timedelta(minutes=age_min)).strftime("%Y-%m-%d %H:%M:%S.%f")
        db_q(
            "INSERT INTO proxies (link, host, port, country, status, security, added_at, "
            "last_test_at, last_ok_at, latency, latency_vless, speed_kbps, source_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                link or self._link(host, security),
                host,
                443,
                "US",
                status,
                security,
                ts,
                ts,
                ts if last_ok else None,
                latency,
                latency,
                speed,
                source_id,
            ),
        )
        return db_q("SELECT id FROM proxies ORDER BY id DESC LIMIT 1")[0]["id"]

    def _source(self, name: str) -> int:
        db_q(
            "INSERT INTO sources (name, url, type, created_at, last_status, last_import) "
            "VALUES (?,?,?,?,?,?)",
            (name, f"https://example.test/{name}", "url", now_utc(), "ok", now_utc()),
        )
        return db_q("SELECT id FROM sources ORDER BY id DESC LIMIT 1")[0]["id"]


class TestSelection(TempDBTestCase):
    def test_measured_profiles_go_before_unmeasured(self):
        old = self._insert("fast-but-unmeasured.test", latency=10, speed=0)
        measured = self._insert("measured.test", latency=500, speed=42_000)

        sel = config_rows()
        ids = [r["id"] for r in sel.rows]
        self.assertEqual(ids[0], measured, "замеренный профиль обязан быть первым")
        self.assertIn(old, ids)
        self.assertEqual(sel.rows[0]["tier"], 1)
        self.assertEqual(sel.rows[1]["tier"], 2)

        # Лимит не должен отдавать слот незамеренному, пока есть замеренный.
        limited = config_rows(1)
        self.assertEqual([r["id"] for r in limited.rows], [measured])

    def test_stale_working_is_excluded_while_fresh_exists(self):
        fresh = self._insert("fresh.test", age_min=5)
        stale = self._insert("stale.test", age_min=10_000)  # ~7 дней

        sel = config_rows()
        ids = [r["id"] for r in sel.rows]
        self.assertIn(fresh, ids)
        self.assertNotIn(stale, ids, "устаревший working не должен попадать в конфиг")
        self.assertGreaterEqual(sel.counts["stale"], 1)

    def test_freshness_fallback_when_nothing_fresh(self):
        stale = self._insert("very-old.test", age_min=10_000)
        sel = config_rows()
        self.assertEqual(sel.fallback, "stale")
        self.assertEqual([r["id"] for r in sel.rows], [stale])

    def test_min_speed_requires_measurement(self):
        Settings.set("min_speed_mbps", "2")
        unmeasured = self._insert("no-speed.test", speed=0)
        slo = self._insert("slow.test", speed=500)          # 0.5 Mbps < 2
        good = self._insert("good.test", speed=5_000)       # 5 Mbps

        sel = config_rows()
        ids = [r["id"] for r in sel.rows]
        self.assertEqual(ids, [good])
        self.assertNotIn(unmeasured, ids, "незамеренный не проходит порог скорости")
        self.assertNotIn(slo, ids, "медленнее порога в конфиг не идёт")
        self.assertEqual(sel.counts["unmeasured"], 1)
        self.assertEqual(sel.counts["slow"], 1)

    def test_min_speed_fallback_to_unmeasured_when_no_measurements(self):
        Settings.set("min_speed_mbps", "2")
        unmeasured = self._insert("no-speed.test", speed=0)
        sel = config_rows()
        self.assertEqual(sel.fallback, "unmeasured")
        self.assertEqual([r["id"] for r in sel.rows], [unmeasured])

    def test_slow_measured_is_preferred_over_unmeasured_in_fallback(self):
        """Замеренный, но медленный узел понятнее незамеренного: он точно жив."""
        Settings.set("min_speed_mbps", "2")
        slow = self._insert("slow.test", speed=800)
        unmeasured = self._insert("no-speed.test", speed=0)
        sel = config_rows()
        self.assertEqual(sel.fallback, "slow")
        self.assertEqual([r["id"] for r in sel.rows], [slow])
        self.assertNotIn(unmeasured, [r["id"] for r in sel.rows])

    def test_require_speed_strict_excludes_unmeasured(self):
        """Строгий режим требует замер даже при min_speed = 0."""
        Settings.set("require_speed", "true")
        measured = self._insert("measured.test", speed=5_000)
        unmeasured = self._insert("no-speed.test", speed=0)
        sel = config_rows()
        self.assertTrue(sel.strict)
        self.assertEqual([r["id"] for r in sel.rows], [measured])
        self.assertNotIn(unmeasured, [r["id"] for r in sel.rows])
        self.assertEqual(sel.counts["unmeasured"], 1)

    def test_require_speed_does_not_fall_back_to_unmeasured(self):
        Settings.set("require_speed", "true")
        self._insert("no-speed.test", speed=0)
        sel = config_rows()
        self.assertEqual(sel.fallback, "")
        self.assertEqual(sel.rows, [])
        self.assertEqual(sel.counts["selected"], 0)

    def test_invalid_link_never_selected(self):
        bad = "vless://11111111-1111-1111-1111-111111111111@bad.test:443?security=reality&pbk=short&type=tcp#US"
        bad_id = self._insert("bad.test", link=bad, security="reality")
        ok_id = self._insert("ok.test")

        sel = config_rows()
        ids = [r["id"] for r in sel.rows]
        self.assertEqual(ids, [ok_id])
        self.assertNotIn(bad_id, ids)
        self.assertEqual(sel.counts["invalid"], 1)

    def test_blocked_country_excluded(self):
        Settings.set("blocked_countries", "US")
        self._insert("us.test")
        se = self._insert("de.test")
        # страна в ссылке US; для второго профиля меняем страну в БД
        db_q("UPDATE proxies SET country='DE' WHERE id=?", (se,))
        sel = config_rows()
        self.assertEqual([r["id"] for r in sel.rows], [se])
        self.assertEqual(sel.counts["blocked"], 1)

    def test_source_quality_affects_tiebreak_for_unmeasured(self):
        weak_sid = self._source("weak")
        strong_sid = self._source("strong")
        weak = self._insert("weak.test", latency=50, source_id=weak_sid)
        strong = self._insert("strong.test", latency=60, source_id=strong_sid)
        # strong: 2 из 2 живых и замеренных; weak: 1 из 5 живых
        self._insert("strong2.test", speed=9_000, source_id=strong_sid)
        for i in range(4):
            self._insert(f"dead{i}.test", status="failed", latency=0, source_id=weak_sid)

        from app.source_quality import invalidate

        invalidate()
        sel = config_rows()
        ids = [r["id"] for r in sel.rows]
        self.assertLess(ids.index(strong), ids.index(weak),
                        "при равном отсутствии замера приоритет у лучшего источника")
        self.assertIn(weak, ids)
        self.assertIn(strong, ids)

    def test_retest_targets_include_stale_and_unmeasured(self):
        self._insert("fresh-measured.test", speed=5_000, age_min=1)
        stale = self._insert("stale.test", speed=5_000, age_min=10_000)
        unmeasured = self._insert("unmeasured.test", speed=0, age_min=1)

        ids = {t["id"] for t in retest_targets()}
        self.assertIn(stale, ids)
        self.assertIn(unmeasured, ids)
        self.assertEqual(len(ids), 2)


class TestOutboundTags(TempDBTestCase):
    def test_tag_is_derived_from_profile_id(self):
        self.assertEqual(node_tag(1), "node1")
        self.assertEqual(node_tag(818246), "node818246")

    def test_config_tags_stable_after_resort(self):
        """Тег не зависит от порядка: пересортировка по скорости его не меняет."""
        from app.xray_configurator import XrayConfigurator

        Settings.set("geo_enabled", "false")
        first = self._insert("slow.test", speed=1_000, latency=10)
        second = self._insert("fast.test", speed=90_000, latency=5)

        cfg = XrayConfigurator().generate_full_config()
        tags = [o["tag"] for o in cfg["outbounds"] if o["tag"].startswith("node")]
        self.assertEqual(tags, [node_tag(second), node_tag(first)])

        # После «пересортировки» (например, у первого выросла скорость) теги
        # остаются привязанными к тем же профилям.
        db_q("UPDATE proxies SET speed_kbps=200000 WHERE id=?", (first,))
        cfg2 = XrayConfigurator().generate_full_config()
        tags2 = [o["tag"] for o in cfg2["outbounds"] if o["tag"].startswith("node")]
        self.assertEqual(tags2, [node_tag(first), node_tag(second)])
        self.assertEqual(set(tags), set(tags2))

    def test_diff_sync_adds_only_new_and_removes_stale(self):
        from app.xray_configurator import XrayConfigurator

        xr = XrayConfigurator()
        known = {"node1", "node2"}
        with mock.patch.object(xr, "known_node_tags", return_value=set(known)), \
                mock.patch.object(xr, "add_outbound", return_value=True) as add, \
                mock.patch.object(
                    xr, "_remove_outbounds", return_value={"node1"}
                ) as remove:
            res = xr._sync_outbounds([{"tag": "node2"}, {"tag": "node3"}])

        add.assert_called_once()
        self.assertEqual(add.call_args[0][0]["tag"], "node3")
        remove.assert_called_once_with(["node1"])
        self.assertEqual(res["added"], 1)
        self.assertEqual(res["attempted"], 1)
        self.assertEqual(res["removed"], 1)
        self.assertEqual(set(Settings.applied_node_tags()), {"node2", "node3"})

    def test_diff_sync_retries_add_after_failed_remove(self):
        """Тег остался в Xray → удаляем его и добавляем заново, а не падаем."""
        from app.xray_configurator import XrayConfigurator

        xr = XrayConfigurator()
        add_results = [False, True]
        with mock.patch.object(xr, "known_node_tags", return_value=set()), \
                mock.patch.object(xr, "add_outbound", side_effect=add_results) as add, \
                mock.patch.object(
                    xr, "_remove_outbounds", return_value={"node9"}
                ) as remove:
            res = xr._sync_outbounds([{"tag": "node9"}])

        self.assertEqual(add.call_count, 2)
        remove.assert_called_once_with(["node9"])
        self.assertEqual(res["added"], 1)
        # Тег всё-таки добавлен, поэтому он не считается удалённым.
        self.assertEqual(res["removed"], 0)
        self.assertEqual(res["failed"], [])
        self.assertEqual(set(Settings.applied_node_tags()), {"node9"})

    def test_apply_all_returns_applied_flag(self):
        """apply_all сообщает, применился ли конфиг: нужно для промежуточных apply."""
        from app.xray_configurator import XrayConfigurator

        xr = XrayConfigurator()
        with mock.patch.object(xr, "_apply_all_impl"):
            self.assertTrue(xr.apply_all(blocking=False))
        xr._apply_lock.acquire()
        try:
            with mock.patch.object(xr, "_apply_all_impl") as impl:
                self.assertFalse(xr.apply_all(blocking=False))
                impl.assert_not_called()
        finally:
            xr._apply_lock.release()

    def test_diff_sync_is_noop_when_everything_applied(self):
        from app.xray_configurator import XrayConfigurator

        xr = XrayConfigurator()
        with mock.patch.object(xr, "known_node_tags", return_value={"node7"}), \
                mock.patch.object(xr, "add_outbound") as add, \
                mock.patch.object(xr, "_remove_outbounds") as remove:
            res = xr._sync_outbounds([{"tag": "node7"}])

        add.assert_not_called()
        remove.assert_not_called()
        self.assertEqual(res["attempted"], 0)
        self.assertEqual(res["removed"], 0)


class TestPortsInConfig(TempDBTestCase):
    """Порты inbound'ов берутся из настроек, а не из констант config.py."""

    def test_generated_config_uses_configured_ports(self):
        from app.xray_configurator import XrayConfigurator

        Settings.set("geo_enabled", "false")
        Settings.set("socks_port", "11080")
        Settings.set("http_port", "11081")
        Settings.set("api_port", "11085")
        Settings.invalidate()

        cfg = XrayConfigurator().generate_full_config()
        by_port = {ib.get("port"): ib.get("protocol") for ib in cfg["inbounds"]}
        self.assertEqual(by_port.get(11080), "socks")
        self.assertEqual(by_port.get(11081), "http")
        self.assertEqual(by_port.get(11085), "dokodemo-door")

    def test_bad_port_falls_back_to_default(self):
        Settings.set("socks_port", "not-a-port")
        Settings.set("http_port", "70000")
        Settings.invalidate()
        self.assertEqual(Settings.socks_port(), 1080)
        self.assertEqual(Settings.http_port(), 1081)


class TestSubscribeUsesSelection(TempDBTestCase):
    def test_subscribe_contains_only_selected_and_marks_fallback(self):
        Settings.set("min_speed_mbps", "2")
        Settings.set("max_active_proxies", "5")
        unmeasured = self._insert("only.test", speed=0, age_min=0)
        self._insert("dead.test", status="failed", latency=0, age_min=0)

        tmp = Path(self._tmpdir.name) / "subscribe.txt"
        with mock.patch.object(app_subscribe, "SUBSCRIBE_FILE", tmp):
            app_subscribe.update_subscribe_cache()

        text = tmp.read_text(encoding="utf-8")
        link = db_q("SELECT link FROM proxies WHERE id=?", (unmeasured,))[0]["link"]
        self.assertIn(link, text)
        self.assertIn("Warning: fallback", text)
        self.assertIn("# Configs: 1 / 1 working / 2 total", text)

    def test_subscribe_strict_drops_unmeasured(self):
        Settings.set("require_speed", "true")
        measured = self._insert("measured.test", speed=5_000)
        unmeasured = self._insert("no-speed.test", speed=0)

        tmp = Path(self._tmpdir.name) / "subscribe.txt"
        with mock.patch.object(app_subscribe, "SUBSCRIBE_FILE", tmp):
            app_subscribe.update_subscribe_cache()

        text = tmp.read_text(encoding="utf-8")
        measured_link = db_q("SELECT link FROM proxies WHERE id=?", (measured,))[0]["link"]
        unmeasured_link = db_q("SELECT link FROM proxies WHERE id=?", (unmeasured,))[0]["link"]
        self.assertIn(measured_link, text)
        self.assertNotIn(unmeasured_link, text)
        self.assertIn("# Strict: only measured profiles", text)


class TestSourceQuality(TempDBTestCase):
    def test_healthy_source_beats_bad_source(self):
        from app.source_quality import collect, invalidate, ranked

        good_sid = self._source("good")
        self._insert("g1.test", speed=5_000, source_id=good_sid)
        self._insert("g2.test", speed=7_000, source_id=good_sid)

        bad_sid = self._source("bad")
        self._insert("b1.test", source_id=bad_sid)
        for i in range(9):
            self._insert(f"bd{i}.test", status="failed", latency=0, source_id=bad_sid)

        invalidate()
        stats = collect(force=True)
        self.assertGreater(stats[good_sid]["score"], stats[bad_sid]["score"])
        self.assertEqual(stats[good_sid]["verdict"], "healthy")
        self.assertIn(stats[bad_sid]["verdict"], ("bad", "weak"))
        self.assertEqual(ranked()[0]["id"], good_sid)

    def test_source_without_profiles_is_inactive(self):
        from app.source_quality import collect, invalidate

        sid = self._source("empty")
        db_q("UPDATE sources SET last_status=NULL, last_import=NULL WHERE id=?", (sid,))
        invalidate()
        stats = collect(force=True)
        self.assertEqual(stats[sid]["verdict"], "inactive")
        self.assertEqual(stats[sid]["score"], 0)

    def test_ok_import_without_links_is_empty(self):
        from app.source_quality import collect, invalidate

        sid = self._source("no-links")
        db_q(
            "UPDATE sources SET last_status='empty', last_added=0, last_duplicates=0, "
            "last_parsed=0 WHERE id=?",
            (sid,),
        )
        invalidate()
        stats = collect(force=True)
        self.assertEqual(stats[sid]["verdict"], "empty")

    def test_import_counters_are_saved(self):
        from app.importer import save_source_status

        sid = self._source("counters")
        save_source_status({
            "id": sid, "status": "ok", "reason": "",
            "added": 0, "duplicates": 361, "parsed": 361,
        })
        row = db_q("SELECT last_added, last_duplicates, last_parsed FROM sources WHERE id=?", (sid,))[0]
        self.assertEqual(row["last_added"], 0)
        self.assertEqual(row["last_duplicates"], 361)
        self.assertEqual(row["last_parsed"], 361)

    def test_broken_import_verdict(self):
        from app.source_quality import collect, invalidate

        sid = self._source("broken")
        self._insert("x.test", source_id=sid)
        db_q("UPDATE sources SET last_status='network_error', last_error='timeout' WHERE id=?", (sid,))
        invalidate()
        stats = collect(force=True)
        self.assertEqual(stats[sid]["verdict"], "broken")
        self.assertIn("связь", stats[sid]["recommendation"])

    def test_duplicate_only_source_verdict(self):
        """0 профилей + все ссылки уже были: это дубли, а не сломанный импорт."""
        from app.source_quality import collect, invalidate

        sid = self._source("dupes")
        db_q(
            "UPDATE sources SET last_status='ok', last_added=0, last_duplicates=361, "
            "last_parsed=361 WHERE id=?",
            (sid,),
        )
        invalidate()
        stats = collect(force=True)
        self.assertEqual(stats[sid]["verdict"], "duplicate")
        self.assertEqual(stats[sid]["verdict_label"], "все дубли")
        self.assertIn("других источников", stats[sid]["recommendation"])


if __name__ == "__main__":
    unittest.main()
