"""Тесты проверки прокси: батч-чекер, TCP-префильтр, backoff.

Запуск: python -m unittest discover -s tests -v

Тесты не требуют бинарника Xray и сети: вместо процесса Xray используется
фейковый launcher, который поднимает локальные http-прокси на портах из
конфига и отвечает 204 (живой профиль) или молчит до таймаута (мёртвый).
"""

import io
import json
import socket
import tempfile
import threading
import time
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

import app.db as app_db
from app.checker import (
    BatchXrayChecker,
    PortReserver,
    probe_median,
    tcp_reachable,
    validate_link,
)
from app.db import Settings, init_db


# ─── Фейковый Xray ───


class FakeProc:
    """Заглушка subprocess.Popen для фейкового launcher'а."""

    _counter = 100000

    def __init__(self, alive=True, servers=None):
        FakeProc._counter += 1
        self.pid = FakeProc._counter
        self._alive = alive
        self._stopped = threading.Event()
        self._servers = servers or []

    def poll(self):
        return None if self._alive else 0

    def wait(self, timeout=None):
        self._stopped.wait(0.05 if timeout is None else timeout)
        return 0

    def stop(self):
        self._alive = False
        self._stopped.set()
        for srv in self._servers:
            srv.stop()
        for srv in self._servers:
            srv.join(timeout=1.0)


class FakeNodeServer(threading.Thread):
    """Локальный http-прокси на порту inbound: отвечает 204 или висит."""

    def __init__(self, port, hang=False, url_aware=False):
        super().__init__(daemon=True)
        self.port = port
        self.hang = hang
        self.url_aware = url_aware
        self._stop_evt = threading.Event()
        self._sock = None

    def run(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", self.port))
            srv.listen(16)
            srv.settimeout(0.2)
            self._sock = srv
        except OSError:
            return
        while not self._stop_evt.is_set():
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
                data = conn.recv(65536)
            except OSError:
                return
            if self.url_aware:
                # Первый (недоступный) URL «висит»: клиент должен уйти на
                # второго кандидата и получить 204.
                if b"/dead" in data:
                    time.sleep(0.4)
                    return
                conn.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                return
            if self.hang:
                time.sleep(1.5)
                return
            conn.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self._stop_evt.set()


class FakeLauncher:
    """Launcher без Xray: читает конфиг, поднимает серверы на портах inbound."""

    def __init__(self, url_aware=False):
        self.starts = 0
        self.procs = []
        self.url_aware = url_aware

    def start(self, config_path, log_path):
        self.starts += 1
        cfg = json.loads(Path(config_path).read_text())
        addresses = []
        for ob in cfg.get("outbounds", []):
            vnext = ob.get("settings", {}).get("vnext", [{}])
            addresses.append(vnext[0].get("address", ""))
        if "poison.test" in addresses:
            proc = FakeProc(alive=False)
            self.procs.append(proc)
            return proc
        servers = []
        for i, ib in enumerate(cfg.get("inbounds", [])):
            hang = addresses[i] == "hang.test"
            srv = FakeNodeServer(
                ib["port"], hang=hang, url_aware=self.url_aware
            )
            srv.start()
            servers.append(srv)
        proc = FakeProc(alive=True, servers=servers)
        self.procs.append(proc)
        return proc

    @staticmethod
    def stop(proc):
        proc.stop()


def make_parsed(server: str, port: int = 443, security: str = "tls") -> dict:
    """Минимальный «распарсенный» профиль для чекера."""
    return {
        "uid": "11111111-2222-3333-4444-555555555555",
        "server": server,
        "host": server,
        "port": port,
        "type": "tcp",
        "security": security,
        "sni": server,
    }


# ─── Тесты чекера ───


class TestPortReserver(unittest.TestCase):
    def test_unique_and_free(self):
        reserver = PortReserver()
        ports = reserver.reserve(10)
        self.assertEqual(len(ports), 10)
        self.assertEqual(len(set(ports)), 10)
        for p in ports:
            self.assertTrue(0 < p < 65536)


class TestValidateLink(unittest.TestCase):
    def test_ok(self):
        self.assertIsNone(validate_link(make_parsed("ok.test")))

    def test_invalid(self):
        self.assertEqual(validate_link(None), "invalid link")
        bad = make_parsed("ok.test")
        bad["port"] = 0
        self.assertEqual(validate_link(bad), "invalid port")
        bad_net = make_parsed("ok.test")
        bad_net["type"] = "mekya"
        self.assertTrue(validate_link(bad_net).startswith("unsupported transport"))

    def test_reality_requires_valid_pbk(self):
        parsed = make_parsed("ok.test", security="reality")
        self.assertEqual(validate_link(parsed), "invalid reality publicKey")
        parsed["pbk"] = "A" * 43  # 32 байта base64url
        self.assertIsNone(validate_link(parsed))


class TestTcpPrefilter(unittest.TestCase):
    def test_open_and_closed_port(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            ok, err = tcp_reachable("127.0.0.1", port, timeout=1.0)
            self.assertTrue(ok, err)
        finally:
            srv.close()
        ok, err = tcp_reachable("127.0.0.1", port, timeout=0.5)
        self.assertFalse(ok)
        self.assertIn("tcp", err)

    def test_unresolvable_host(self):
        ok, err = tcp_reachable("no-such-host.invalid", 443, timeout=1.0)
        self.assertFalse(ok)
        self.assertIn(err, {"dns lookup failed", "tcp unreachable"})


class TestBatchChecker(unittest.TestCase):
    def setUp(self):
        patcher = unittest.mock.patch.object(
            Settings, "probe_url", classmethod(lambda cls: "http://probe.local/204")
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        # Один кандидат: фейковый сервер отвечает на любой URL, а реальный
        # каталог в тесте дал бы лишние сетевые попытки.
        patcher = unittest.mock.patch(
            "app.checker.netcheck.probe_url_candidates",
            return_value=["http://probe.local/204"],
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        cache_patcher = unittest.mock.patch.object(
            Settings, "ping_samples", classmethod(lambda cls: 2)
        )
        cache_patcher.start()
        self.addCleanup(cache_patcher.stop)
        # Повторы проверяются отдельным тестом; здесь важны тайминги.
        retry_patcher = unittest.mock.patch.object(
            Settings, "probe_retries", classmethod(lambda cls: 0)
        )
        retry_patcher.start()
        self.addCleanup(retry_patcher.stop)

    def test_batch_ok(self):
        launcher = FakeLauncher()
        checker = BatchXrayChecker(launcher=launcher)
        items = [(i, make_parsed("ok.test")) for i in range(1, 4)]
        results = checker.check(items, timeout=1.0, batch_size=4)
        self.assertEqual(len(results), 3)
        for key in (1, 2, 3):
            self.assertTrue(results[key]["ok"], results[key])
            self.assertGreater(results[key]["latency"], 0)
        self.assertEqual(launcher.starts, 1, "вся пачка должна уйти в один процесс")

    def test_falls_back_to_working_probe_url(self):
        """Проба ушла на мёртвый URL — профиль проверяется через второй кандидат."""
        launcher = FakeLauncher(url_aware=True)
        checker = BatchXrayChecker(launcher=launcher)
        items = [(1, make_parsed("ok.test"))]
        with mock.patch.object(
            Settings, "probe_retries", classmethod(lambda cls: 1)
        ):
            results = checker.check(
                items,
                timeout=0.3,
                batch_size=1,
                probe_urls=["http://probe.local/dead", "http://probe.local/alive"],
            )
        self.assertTrue(results[1]["ok"], results[1])
        self.assertEqual(checker.last_probe_stats.best(), "http://probe.local/alive")
        self.assertEqual(checker.last_probe_stats.ok_count("http://probe.local/dead"), 0)

    def test_invalid_config_isolated_without_starting_process(self):
        """Битый outbound изолируется быстрой проверкой конфига, а не стартом Xray."""
        launcher = FakeLauncher()
        checker = BatchXrayChecker(launcher=launcher)

        def fake_test_config(path):
            text = Path(path).read_text(encoding="utf-8")
            if "poison.test" in text:
                return False, "bad outbound"
            return True, ""

        items = [
            (i, make_parsed("poison.test" if i == 3 else "ok.test"))
            for i in (1, 2, 3, 4)
        ]
        with mock.patch.object(checker, "_test_config", side_effect=fake_test_config):
            results = checker.check(items, timeout=1.0, batch_size=4, batch_limit=5)
        self.assertEqual(results[3]["error"], "xray config invalid: bad outbound")
        for good in (1, 2, 4):
            self.assertTrue(results[good]["ok"], results[good])

    def test_prevalidation_drops_invalid_without_bisect(self):
        """Битый профиль отсекается поштучно: пачка не делится и не тормозит."""
        launcher = FakeLauncher()
        checker = BatchXrayChecker(launcher=launcher)

        def fake_test(path):
            text = Path(path).read_text(encoding="utf-8")
            if "poison.test" in text:
                return False, "Failed to start: invalid transport"
            return True, ""

        items = [
            (i, make_parsed("poison.test" if i == 2 else "ok.test"))
            for i in range(1, 5)
        ]
        with mock.patch.object(
            checker, "_test_config", side_effect=fake_test
        ) as test_cfg:
            results = checker.check(items, timeout=1.0, batch_size=4)
        self.assertEqual(
            results[2]["error"],
            "xray config invalid: Failed to start: invalid transport",
        )
        for good in (1, 3, 4):
            self.assertTrue(results[good]["ok"], results[good])
        self.assertEqual(
            test_cfg.call_count, 4,
            "каждый профиль проверяется один раз, повторного теста пачки нет",
        )
        self.assertEqual(launcher.starts, 1, "валидные профили идут одной пачкой")

    def test_test_config_reason_from_stdout(self):
        """Xray печатает причину в stdout («Failed to start: …»), не только в stderr."""
        checker = BatchXrayChecker(launcher=FakeLauncher())
        run_result = mock.Mock(
            returncode=23, stdout="Failed to start: bad outbound", stderr=""
        )
        with mock.patch("app.checker.subprocess.run", return_value=run_result):
            ok, detail = checker._test_config("config.json")
        self.assertFalse(ok)
        self.assertIn("bad outbound", detail)

    def test_config_test_command_falls_back_for_old_xray(self):
        checker = BatchXrayChecker(launcher=FakeLauncher())
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(list(cmd))
            if "run" not in cmd:
                # Старый/нестандартный бинарник не понял первый вариант.
                return mock.Mock(
                    returncode=2,
                    stderr="flag provided but not defined: -test",
                    stdout="",
                )
            return mock.Mock(returncode=0, stderr="", stdout="")

        with mock.patch("app.checker.subprocess.run", side_effect=fake_run):
            ok, detail = checker._test_config("config.json")
        self.assertTrue(ok)
        self.assertEqual(detail, "")
        self.assertEqual(len(calls), 2, "должны попробовать оба варианта команды")
        self.assertIn("run", calls[1])

    def test_stuck_batch_is_cut_by_limit(self):
        """Зависшая пачка не блокирует прогон: остаток помечается timeout'ом."""
        launcher = FakeLauncher()
        checker = BatchXrayChecker(launcher=launcher)

        def slow_probe(*args, **kwargs):
            time.sleep(2.0)
            return True, 5, "", 1

        items = [(1, make_parsed("ok.test")), (2, make_parsed("ok.test"))]
        started = time.time()
        with mock.patch("app.checker.probe_median", side_effect=slow_probe):
            results = checker.check(
                items, timeout=1.0, batch_size=2, batch_limit=0.4
            )
        elapsed = time.time() - started
        self.assertLess(elapsed, 1.5, "пачка должна обрываться по лимиту")
        self.assertEqual(results[1]["error"], "probe batch timeout")
        self.assertEqual(results[2]["error"], "probe batch timeout")

    def test_batch_mixed(self):
        launcher = FakeLauncher()
        checker = BatchXrayChecker(launcher=launcher)
        items = [
            (1, make_parsed("ok.test")),
            (2, make_parsed("hang.test")),
            (3, make_parsed("ok.test")),
        ]
        started = time.time()
        results = checker.check(items, timeout=1.0, batch_size=8)
        elapsed = time.time() - started
        self.assertTrue(results[1]["ok"])
        self.assertFalse(results[2]["ok"])
        self.assertEqual(results[2]["error"], "timeout")
        self.assertTrue(results[3]["ok"])
        self.assertLess(elapsed, 3.5, "пробы должны идти параллельно, а не по очереди")

    def test_bisect_on_poison_config(self):
        launcher = FakeLauncher()
        checker = BatchXrayChecker(launcher=launcher)
        items = [
            (1, make_parsed("ok.test")),
            (2, make_parsed("poison.test")),
            (3, make_parsed("ok.test")),
            (4, make_parsed("ok.test")),
        ]
        results = checker.check(items, timeout=1.0, batch_size=4)
        self.assertTrue(results[1]["ok"])
        self.assertFalse(results[2]["ok"])
        self.assertIn("xray start failed", results[2]["error"])
        self.assertTrue(results[3]["ok"])
        self.assertTrue(results[4]["ok"])
        self.assertGreater(launcher.starts, 1, "должен был сработать bisect")

    def test_cancel(self):
        launcher = FakeLauncher()
        checker = BatchXrayChecker(launcher=launcher)
        cancel = threading.Event()
        cancel.set()
        items = [(i, make_parsed("ok.test")) for i in range(1, 5)]
        results = checker.check(items, timeout=1.0, batch_size=2, cancel=cancel)
        self.assertEqual(results, {})

    def test_cancel_mid_run_does_not_mark_failed(self):
        """Отмена не должна превращать непроверенные профили в failed."""
        launcher = FakeLauncher()
        checker = BatchXrayChecker(launcher=launcher)
        cancel = threading.Event()
        seen = []

        def on_result(key, result):
            seen.append((key, result))
            if len(seen) >= 2:
                cancel.set()

        items = [(i, make_parsed("ok.test")) for i in range(1, 5)]
        results = checker.check(
            items, timeout=1.0, batch_size=2, cancel=cancel, on_result=on_result
        )
        self.assertEqual(len(results), 2, "после отмены новые пачки не запускаются")
        for key, result in results.items():
            self.assertTrue(result["ok"], result)
            self.assertNotEqual(result["error"], "canceled")


class TestProbeMedian(unittest.TestCase):
    def test_median_of_samples(self):
        srv = FakeNodeServer(0)  # порт выберем вручную ниже
        # поднимаем сервер на свободном порту
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        srv.port = port
        srv.start()
        time.sleep(0.1)
        try:
            ok, lat, err, samples = probe_median(port, 1.0, "http://probe.local/204", 2)
            self.assertTrue(ok, err)
            self.assertGreater(lat, 0)
            self.assertGreaterEqual(samples, 1)
        finally:
            srv.stop()


# ─── Тесты БД: backoff, due-выборка, автоочистка ───


class TempDBTestCase(unittest.TestCase):
    """Подменяет файл БД на временный: реальный proxies.db не трогаем."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self._old_db = app_db.DATABASE
        app_db.DATABASE = Path(self._tmpdir.name) / "test.db"
        # сбрасываем кэши и привязанное к потоку соединение
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


class TestBackoff(TempDBTestCase):
    def _add(self, link_suffix="ok.test"):
        from app.utils import now_utc

        app_db.db_q(
            "INSERT INTO proxies (link, host, port, status, added_at) VALUES (?,?,?,?,?)",
            (f"vless://uuid@{link_suffix}:443", link_suffix, 443, "pending", now_utc()),
        )
        return app_db.db_q("SELECT id FROM proxies ORDER BY id DESC LIMIT 1")[0]["id"]

    def test_failure_sets_backoff_and_success_resets(self):
        from app.proxy_manager import ProxyManager

        pid = self._add()
        app_db.db_q(
            "UPDATE proxies SET speed_kbps=1234, speed_max_kbps=2345 WHERE id=?", (pid,)
        )
        ProxyManager._update_vless_status(pid, False, 0, "timeout")
        row = app_db.db_q("SELECT * FROM proxies WHERE id=?", (pid,))[0]
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["speed_kbps"], 0)
        self.assertEqual(row["speed_max_kbps"], 0)
        self.assertEqual(row["fail_count"], 1)
        self.assertIsNotNone(row["next_test_at"])
        first_backoff = row["next_test_at"]

        ProxyManager._update_vless_status(pid, False, 0, "timeout")
        row = app_db.db_q("SELECT * FROM proxies WHERE id=?", (pid,))[0]
        self.assertEqual(row["fail_count"], 2)
        self.assertGreater(row["next_test_at"], first_backoff)

        ProxyManager._update_vless_status(pid, True, 123, "")
        row = app_db.db_q("SELECT * FROM proxies WHERE id=?", (pid,))[0]
        self.assertEqual(row["status"], "working")
        self.assertEqual(row["fail_count"], 0)
        self.assertIsNone(row["next_test_at"])
        self.assertEqual(row["latency_vless"], 123)

    def test_speed_stage_applies_incrementally(self):
        """Замер скорости обновляет конфиг/подписку, не дожидаясь конца стадии."""
        import app.proxy_manager as pm_mod

        def link(host):
            return (
                "vless://11111111-2222-3333-4444-555555555555@"
                f"{host}:443?security=tls&type=tcp"
            )

        pm = pm_mod.ProxyManager()
        rows = [
            {"id": 1, "link": link("one.test"), "host": "one.test"},
            {"id": 2, "link": link("two.test"), "host": "two.test"},
        ]
        pm._start_xray = lambda parsed: (object(), "/tmp/x", 12345, "")
        pm._measure_kbps = lambda port, window: (1000, 2000)
        pm._stop_xray = lambda proc, tmp: None
        pm._set_current = lambda *a, **k: None
        pm._stage_advance = lambda *a, **k: None
        calls = []
        pm._apply_incremental = lambda reason: calls.append(reason) or True

        with mock.patch.object(pm_mod, "INCREMENTAL_APPLY_SEC", 0):
            pm._stage_speed(rows, apply_incremental=True)
        self.assertEqual(calls, ["замерено 1 профилей"],
                         "apply должен случиться между замерами, а не в конце")

    def test_due_rows_skips_future(self):
        from app.proxy_manager import proxy_manager

        pid_ok = self._add("ok.test")
        pid_wait = self._add("wait.test")
        app_db.db_q(
            "UPDATE proxies SET next_test_at=datetime('now', '+3600 seconds') WHERE id=?",
            (pid_wait,),
        )
        ids = {r["id"] for r in proxy_manager._due_rows()}
        self.assertIn(pid_ok, ids)
        self.assertNotIn(pid_wait, ids)

    def test_cleanup_only_after_three_fails(self):
        from app.proxy_manager import proxy_manager

        pid1 = self._add("one.test")
        pid2 = self._add("two.test")
        app_db.db_q(
            "UPDATE proxies SET status='failed', fail_count=1 WHERE id=?", (pid1,)
        )
        app_db.db_q(
            "UPDATE proxies SET status='failed', fail_count=3 WHERE id=?", (pid2,)
        )
        proxy_manager._cleanup_failed()
        left = {r["id"] for r in app_db.db_q("SELECT id FROM proxies")}
        self.assertIn(pid1, left, "упавший один раз не должен удаляться")
        self.assertNotIn(pid2, left)


class TestEnrichment(TempDBTestCase):
    def test_batch_enrich_uses_cached_ips(self):
        from app.utils import enrich_countries_once, now_utc
        import app.utils as utils

        app_db.db_q(
            "INSERT INTO proxies (link, host, port, country, country_verified, status, added_at) "
            "VALUES (?,?,?,?,?,?,?)",
            ("vless://u@a.test:443", "a.test", 443, "", 0, "working", now_utc()),
        )
        app_db.db_q(
            "INSERT INTO proxies (link, host, port, country, country_verified, status, added_at) "
            "VALUES (?,?,?,?,?,?,?)",
            ("vless://u@b.test:443", "b.test", 443, "", 0, "working", now_utc()),
        )
        utils._geo_ip_cache.clear()
        utils._geo_neg_cache.clear()
        utils._geo_host_cache.clear()

        calls = []

        def fake_batch(ips):
            calls.append(list(ips))
            return {ip: "NL" for ip in ips}

        fake_ips = {"a.test": "10.0.0.1", "b.test": "10.0.0.2"}
        old_batch = utils._ipapi_batch
        old_resolve = utils.resolve_host
        utils._ipapi_batch = fake_batch
        utils.resolve_host = lambda host: fake_ips.get(host, "")
        try:
            corrected = enrich_countries_once()
        finally:
            utils._ipapi_batch = old_batch
            utils.resolve_host = old_resolve
        self.assertEqual(corrected, 2)
        rows = app_db.db_q("SELECT country, country_verified FROM proxies")
        self.assertEqual({r["country"] for r in rows}, {"NL"})
        self.assertEqual({r["country_verified"] for r in rows}, {1})
        self.assertEqual(len(calls), 1, "оба адреса должны уйти одним батчем")

        # повторный проход ничего не делает: профили уже верифицированы
        self.assertEqual(enrich_countries_once(), 0)

    def test_only_working_profiles_are_enriched(self):
        """Мёртвые и непроверенные не тратят DNS/ip-api."""
        import app.utils as utils
        from app.utils import enrich_countries_once, now_utc

        for status in ("pending", "failed"):
            app_db.db_q(
                "INSERT INTO proxies (link, host, port, country, country_verified, status, added_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (f"vless://u@{status}.test:443", f"{status}.test", 443, "", 0, status, now_utc()),
            )
        utils._geo_ip_cache.clear()
        utils._geo_neg_cache.clear()
        utils._geo_host_cache.clear()
        called = []
        old_batch = utils._ipapi_batch
        old_resolve = utils.resolve_host
        utils._ipapi_batch = lambda ips: called.append(list(ips)) or {}
        utils.resolve_host = lambda host: "10.0.0.9"
        try:
            corrected = enrich_countries_once()
        finally:
            utils._ipapi_batch = old_batch
            utils.resolve_host = old_resolve
        self.assertEqual(corrected, 0)
        self.assertEqual(called, [], "для нерабочих профилей ip-api не вызывается")

    def test_country_fallback_parses_codes(self):
        """ip-api.com недоступен → страны берутся из HTTPS-резерва."""
        import app.utils as utils

        class Resp:
            def __init__(self, payload):
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return json.dumps(self.payload).encode()

        def fake_urlopen(req, timeout=None, context=None):
            ip = str(getattr(req, "full_url", req)).rsplit("/", 1)[-1]
            if ip == "8.8.8.8":
                return Resp({"ip": ip, "country": "US"})
            raise OSError("blocked")

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            out = utils._country_is_batch(["8.8.8.8", "10.0.0.1"])
        self.assertEqual(out, {"8.8.8.8": "US"})

    def test_ipapi_cooldown_goes_straight_to_fallback(self):
        """После первого таймаута 10 минут не ждём ip-api, а сразу берём резерв."""
        import app.utils as utils

        old_down = utils._geo_ipapi_down_until
        old_last = utils._geo_last_request
        utils._geo_ipapi_down_until = 0.0
        utils._geo_last_request = time.time()
        calls = {"urlopen": 0, "fallback": 0}

        def failing_urlopen(*args, **kwargs):
            calls["urlopen"] += 1
            raise OSError("timed out")

        def fake_fallback(ips):
            calls["fallback"] += 1
            return {ip: "US" for ip in ips}

        try:
            with mock.patch("urllib.request.urlopen", side_effect=failing_urlopen), \
                    mock.patch.object(utils, "_country_is_batch", side_effect=fake_fallback):
                first = utils._ipapi_batch(["8.8.8.8"])
                second = utils._ipapi_batch(["9.9.9.9"])
        finally:
            utils._geo_ipapi_down_until = old_down
            utils._geo_last_request = old_last
        self.assertEqual(first, {"8.8.8.8": "US"})
        self.assertEqual(second, {"9.9.9.9": "US"})
        self.assertEqual(calls["urlopen"], 1, "в cooldown ip-api не дёргаем повторно")
        self.assertEqual(calls["fallback"], 2)


class TestStageCheckIntegration(TempDBTestCase):
    """Стадия проверки целиком: чекер → БД → прогресс."""

    def setUp(self):
        super().setUp()
        app_db.db_q(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('speed_test_enabled', 'false')"
        )
        app_db.db_q(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('apply_after_test', 'false')"
        )
        Settings.invalidate()
        for patcher in (
            mock.patch.object(
                Settings, "probe_url", classmethod(lambda cls: "http://probe.local/204")
            ),
            mock.patch.object(Settings, "ping_samples", classmethod(lambda cls: 2)),
            mock.patch.object(Settings, "tcp_prefilter", classmethod(lambda cls: False)),
            mock.patch.object(Settings, "check_batch_size", classmethod(lambda cls: 8)),
            mock.patch.object(Settings, "probe_retries", classmethod(lambda cls: 0)),
            mock.patch(
                "app.checker.netcheck.probe_url_candidates",
                return_value=["http://probe.local/204"],
            ),
            mock.patch(
                "app.proxy_manager.netcheck.ensure_probe_url",
                return_value="http://probe.local/204",
            ),
            mock.patch(
                "app.proxy_manager.netcheck.probe_url_candidates",
                return_value=["http://probe.local/204"],
            ),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def _add_proxy(self, host: str) -> int:
        """Добавляет профиль. UUID уникален на вызов: link — UNIQUE."""
        from app.utils import now_utc

        self._seq = getattr(self, "_seq", 0) + 1
        uid = f"11111111-2222-3333-4444-{self._seq:012d}"
        link = (
            f"vless://{uid}@{host}:443?security=tls&type=tcp&sni={host}#NL"
        )
        app_db.db_q(
            "INSERT INTO proxies (link, host, port, status, added_at) VALUES (?,?,?,?,?)",
            (link, host, 443, "pending", now_utc()),
        )
        return app_db.db_q("SELECT id FROM proxies ORDER BY id DESC LIMIT 1")[0]["id"]

    def test_stage_check_updates_statuses(self):
        from app.proxy_manager import proxy_manager

        ok_id = self._add_proxy("ok.test")
        dead_id = self._add_proxy("hang.test")
        ok_id2 = self._add_proxy("ok.test")
        rows = [dict(r) for r in app_db.db_q("SELECT id, link, host FROM proxies")]

        proxy_manager._checker = BatchXrayChecker(launcher=FakeLauncher())
        proxy_manager._cancel.clear()
        proxy_manager._begin_run("test")
        proxy_manager._begin_stage("check", "Проверка", len(rows))
        ok_cnt, done_cnt = proxy_manager._stage_check(rows, 1.0)
        proxy_manager._end_stage()

        self.assertEqual((ok_cnt, done_cnt), (2, 3))
        got = {
            r["id"]: (r["status"], r["latency_vless"], r["fail_count"])
            for r in app_db.db_q("SELECT id, status, latency_vless, fail_count FROM proxies")
        }
        self.assertEqual(got[ok_id][0], "working")
        self.assertGreater(got[ok_id][1], 0)
        self.assertEqual(got[ok_id][2], 0)
        self.assertEqual(got[dead_id][0], "failed")
        self.assertEqual(got[dead_id][2], 1)
        self.assertEqual(got[ok_id2][0], "working")
        snap = proxy_manager.progress_snapshot()
        self.assertEqual(snap["done"], 3)
        self.assertEqual(snap["ok"], 2)
        self.assertEqual(snap["stages"][0]["status"], "done")

    def test_pipeline_without_speed(self):
        """Конвейер без импорта и без скорости: проверка → применение выключено."""
        from app.proxy_manager import proxy_manager

        self._add_proxy("ok.test")
        self._add_proxy("hang.test")
        rows = [dict(r) for r in app_db.db_q("SELECT id, link, host FROM proxies")]

        proxy_manager._checker = BatchXrayChecker(launcher=FakeLauncher())
        ok_cnt, done_cnt = proxy_manager._execute_pipeline(rows, "db-check")
        self.assertEqual((ok_cnt, done_cnt), (1, 2))
        snap = proxy_manager.progress_snapshot()
        self.assertFalse(snap["running"])
        self.assertEqual(snap["last_label"], "db-check")
        keys = [s["key"] for s in snap["stages"]]
        self.assertEqual(keys, ["check", "speed"])
        self.assertEqual(snap["stages"][1]["status"], "skipped")


class TestSpeedStage(TempDBTestCase):
    """Стадия скорости: ротация попыток и терпимость к недоступному URL."""

    @staticmethod
    def _link(host):
        return (
            "vless://11111111-2222-3333-4444-555555555555@"
            f"{host}:443?security=tls&type=tcp"
        )

    def test_continues_after_five_profiles_without_data(self):
        """Плохие первые профили не прерывают стадию — очередь должна двигаться."""
        import app.proxy_manager as pm_mod

        pm = pm_mod.ProxyManager()
        rows = [
            {"id": i, "link": self._link(f"h{i}.test"), "host": f"h{i}.test"}
            for i in range(1, 9)
        ]
        starts = []
        pm._start_xray = lambda parsed: (starts.append(1) or object(), "/tmp/x", 12345, "")
        pm._measure_kbps = lambda port, window: (0, 0)
        pm._stop_xray = lambda proc, tmp: None
        pm._set_current = lambda *a, **k: None
        pm._stage_advance = lambda *a, **k: None

        pm._stage_speed(rows)
        self.assertEqual(len(starts), 8, "стадия проходит весь список, а не 5 профилей")

    def test_speed_rows_rotate_never_tried_first(self):
        """Очередь замеров: никогда не пробовали → старые попытки → замеренные."""
        from app.proxy_manager import ProxyManager
        from app.utils import now_utc

        rows = [
            (1, "a.test", 10, 0, None, 0, None),   # никогда не замеряли
            (2, "b.test", 20, 0, "2026-01-01", 1, None),  # старая неудачная попытка
            (3, "c.test", 30, 500, None, 0, None),        # замерен
            (4, "d.test", 40, 0, "2026-06-01", 3, None),  # недавняя неудачная попытка
        ]
        for pid, host, lat, kbps, tested_at, fails, _ in rows:
            app_db.db_q(
                "INSERT INTO proxies (link, host, port, status, added_at, "
                "latency_vless, speed_kbps, speed_tested_at, speed_fail_count) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    f"vless://uuid@{host}:443", host, 443, "working",
                    now_utc(), lat, kbps, tested_at, fails,
                ),
            )
        pm = ProxyManager()
        ordered = [r["id"] for r in pm._speed_rows([1, 2, 3, 4])]
        self.assertEqual(ordered, [1, 2, 4, 3])

    def test_does_not_abort_if_speed_appears(self):
        import app.proxy_manager as pm_mod

        pm = pm_mod.ProxyManager()
        rows = [
            {"id": i, "link": self._link(f"h{i}.test"), "host": f"h{i}.test"}
            for i in range(1, 8)
        ]
        calls = {"n": 0}

        def measure(port, window):
            calls["n"] += 1
            return (0, 0) if calls["n"] <= 4 else (1000, 2000)

        pm._start_xray = lambda parsed: (object(), "/tmp/x", 12345, "")
        pm._measure_kbps = measure
        pm._stop_xray = lambda proc, tmp: None
        pm._set_current = lambda *a, **k: None
        pm._stage_advance = lambda *a, **k: None

        pm._stage_speed(rows)
        self.assertEqual(calls["n"], 7, "если данные пошли — стадия не прерывается")


class TestSpeedUrlCache(unittest.TestCase):
    """URL замера скорости: недоступный уходит назад, рабочий — первым."""

    def test_url_order(self):
        from app.proxy_manager import ProxyManager, _backoff_seconds

        pm = ProxyManager()
        with mock.patch.object(
            Settings, "get", staticmethod(lambda k, d=None: "http://primary/10mb")
        ):
            self.assertEqual(pm._speed_urls()[0], "http://primary/10mb")
            pm._speed_failed["http://primary/10mb"] = 2
            self.assertNotEqual(
                pm._speed_urls()[0], "http://primary/10mb",
                "URL, дважды не давший данных, не должен пробоваться первым",
            )
            pm._speed_url = "https://speed.cloudflare.com/__down?bytes=10000000"
            self.assertEqual(pm._speed_urls()[0], pm._speed_url)

        # backoff растёт с числом падений и упирается в максимум
        self.assertEqual(_backoff_seconds(1), 900)
        self.assertEqual(_backoff_seconds(2), 3600)
        self.assertEqual(_backoff_seconds(3), 10800)
        self.assertEqual(_backoff_seconds(10), 43200)
        self.assertEqual(_backoff_seconds(0), 900)

    def test_measure_url_returns_error_reason(self):
        """Ошибка замера должна быть видна в логе, а не превращаться в «0 kbps»."""
        from app.proxy_manager import ProxyManager

        with mock.patch("app.proxy_manager.urllib.request.build_opener") as build:
            build.return_value.open.side_effect = OSError(
                "Tunnel connection failed: 400 Bad Request"
            )
            avg, peak, err = ProxyManager._measure_url_kbps(
                1, "http://bad.test/10mb", 1, 0, 2
            )
        self.assertEqual((avg, peak), (0, 0))
        self.assertIn("Tunnel connection failed", err)

    def test_measure_url_includes_xray_dial_error_from_503(self):
        """503 от Xray содержит причину, почему exit-нода не открыла цель."""
        from app.proxy_manager import ProxyManager

        def fake_open(*args, **kwargs):
            raise urllib.error.HTTPError(
                "http://mirror.test/10mb",
                503,
                "Service Unavailable",
                None,
                io.BytesIO("failed to dial mirror.test:80: i/o timeout".encode()),
            )

        with mock.patch("app.proxy_manager.urllib.request.build_opener") as build:
            build.return_value.open.side_effect = fake_open
            avg, peak, err = ProxyManager._measure_url_kbps(
                1, "http://mirror.test/10mb", 1, 0, 2
            )
        self.assertEqual((avg, peak), (0, 0))
        self.assertIn("503", err)
        self.assertIn("failed to dial mirror.test:80", err)

    def test_measure_connect_tunnel_speed(self):
        """CONNECT-туннель: запрос по IP, настоящий Host внутри туннеля."""
        from app.proxy_manager import ProxyManager

        seen = {}

        def serve(srv):
            conn, _ = srv.accept()
            try:
                data = b""
                while b"\r\n\r\n" not in data:
                    data += conn.recv(4096)
                conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                req = b""
                while b"\r\n\r\n" not in req:
                    req += conn.recv(4096)
                seen["req"] = req.decode("utf-8", "replace")
                body = b"x" * 65536
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body
                )
            finally:
                conn.close()

        # Локальный тест-сервер иногда закрывает сокет раньше, чем клиент
        # прочитает тело, поэтому пробуем несколько раз.
        result = (0, 0, "not run")
        for _ in range(4):
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            port = srv.getsockname()[1]
            seen.clear()
            t = threading.Thread(target=serve, args=(srv,), daemon=True)
            t.start()
            try:
                result = ProxyManager._measure_connect_kbps(
                    port,
                    {"ip": "127.0.0.1", "host": "ftp.test", "port": 80, "path": "/f.bin"},
                    3,
                    0,
                    2,
                )
            finally:
                srv.close()
                t.join(timeout=2)
            if result[0] > 0:
                break
        avg, peak, err = result
        self.assertGreater(avg, 0, err)
        self.assertIn("Host: ftp.test", seen["req"])

    def test_ip_endpoint_bypasses_domain(self):
        """Домен резолвится на панели, запрос пойдёт на IP с исходным Host."""
        from app.proxy_manager import ProxyManager

        ep = ProxyManager._ip_endpoint("http://localhost:8080/a/b?x=1")
        self.assertIsNotNone(ep)
        self.assertEqual(ep["ip"], "127.0.0.1")
        self.assertEqual(ep["host"], "localhost")
        self.assertEqual(ep["port"], 8080)
        self.assertEqual(ep["path"], "/a/b?x=1")
        self.assertIsNone(ProxyManager._ip_endpoint("https://example.test/10mb"))

    def test_manual_override_url_goes_first(self):
        """Ручной тест одного профиля может подставить свой URL замера."""
        from app.proxy_manager import ProxyManager

        pm = ProxyManager()
        pm._speed_url_override = "http://my.test/10mb"
        self.assertEqual(pm._speed_urls()[0], "http://my.test/10mb")

    def test_measure_kbps_records_reason_once(self):
        from app.proxy_manager import ProxyManager

        pm = ProxyManager()
        pm._speed_urls = lambda: ["http://bad.test/10mb"]
        pm._measure_url_kbps = lambda *a, **k: (
            0, 0, "SSLError: certificate verify failed"
        )
        with mock.patch.object(
            Settings, "min_speed_kbps", staticmethod(lambda: 0)
        ), mock.patch.object(
            Settings, "speed_test_adaptive_sec", staticmethod(lambda: 3)
        ):
            self.assertEqual(pm._measure_kbps(1234, 1), (0, 0))
        self.assertEqual(
            pm._speed_error_reasons["http://bad.test/10mb"],
            "SSLError: certificate verify failed",
        )


if __name__ == "__main__":
    unittest.main()
