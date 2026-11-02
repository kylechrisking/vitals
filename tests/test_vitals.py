"""Offline tests: config, checks against local servers, the up/down logic,
quiet hours, maintenance, persistence, the Sett feed, notifiers and the page."""
import json
import os
import socket
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="vitals-test-")
os.environ["VITALS_DATA"] = TMP

from vitals import checks, config, notify  # noqa: E402
from vitals.checks import Result  # noqa: E402
from vitals.config import Check, Config  # noqa: E402
from vitals.monitor import Monitor, fmt_duration  # noqa: E402
from vitals.server import make_handler  # noqa: E402
from vitals.sett import SettFeed  # noqa: E402


class Now:
    """An executor that runs work immediately, so alerts can be asserted on."""
    def submit(self, fn, *a, **k):
        fn(*a, **k)


class Fake(BaseHTTPRequestHandler):
    """A tiny local web server: GET answers from `routes`, POSTs are recorded."""
    routes: dict = {}
    posts: list = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        code, body, headers = self.routes.get(self.path.split("?")[0], (404, b"nope", {}))
        self.send_response(code)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.posts.append((self.path, dict(self.headers), self.rfile.read(n)))
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


def serve(handler):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


def stop(httpd):
    httpd.shutdown()
    httpd.server_close()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ConfigLoad(unittest.TestCase):
    def test_checks_notifiers_and_secrets(self):
        d = Path(tempfile.mkdtemp())
        (d / "vitals.toml").write_text('''
title = "Lab"
[[check]]
name = "Router"
type = "ping"
target = "10.0.0.1"
[[check]]
name = "Broken"
type = "carrier-pigeon"
target = "x"
[[notify]]
name = "phone"
type = "ntfy"
url = "https://ntfy.sh/x"
''')
        (d / "secrets.toml").write_text('[[notify]]\nname = "phone"\ntoken = "tk_123"\n[tokens]\nme = "abc"\n')
        os.environ.update(VITALS_CONFIG=str(d / "vitals.toml"), VITALS_SECRETS=str(d / "secrets.toml"))
        try:
            cfg = config.load()
        finally:
            del os.environ["VITALS_CONFIG"], os.environ["VITALS_SECRETS"]
        self.assertEqual([c.name for c in cfg.checks], ["Router"])
        self.assertEqual(len(cfg.errors), 1)
        self.assertEqual(cfg.notifiers, [{"name": "phone", "type": "ntfy", "url": "https://ntfy.sh/x", "token": "tk_123",
                                         "source": "config"}])
        self.assertEqual(cfg.tokens, {"me": "abc"})


class Checks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Fake.routes = {"/ok": (200, b"hello world", {}), "/err": (503, b"down", {})}
        cls.httpd, cls.base = serve(Fake)

    @classmethod
    def tearDownClass(cls):
        stop(cls.httpd)

    def test_http(self):
        self.assertTrue(checks.run(Check("a", "http", f"{self.base}/ok")).ok)
        self.assertFalse(checks.run(Check("a", "http", f"{self.base}/err")).ok)
        self.assertTrue(checks.run(Check("a", "http", f"{self.base}/err", expect_status=[503])).ok)
        r = checks.run(Check("a", "http", f"{self.base}/ok", contains="goodbye"))
        self.assertFalse(r.ok)
        self.assertIn("doesn't contain", r.detail)

    def test_tcp(self):
        port = self.httpd.server_address[1]
        self.assertTrue(checks.run(Check("a", "tcp", f"127.0.0.1:{port}")).ok)
        self.assertFalse(checks.run(Check("a", "tcp", f"127.0.0.1:{free_port()}", timeout=1)).ok)
        self.assertFalse(checks.run(Check("a", "tcp", "no-port-here")).ok)

    def test_dns(self):
        self.assertTrue(checks.run(Check("a", "dns", "localhost")).ok)
        self.assertFalse(checks.run(Check("a", "dns", "localhost", expect="10.9.9.9")).ok)

    def test_ping_without_ping_binary_is_a_clear_failure(self):
        r = checks.run(Check("a", "ping", "127.0.0.1", timeout=1))
        self.assertTrue(r.ok or "reply" in r.detail or "ping" in r.detail)

    def test_cert_expiry_reader(self):
        import shutil
        import subprocess
        if not shutil.which("openssl"):
            self.skipTest("openssl not installed")
        d = tempfile.mkdtemp()
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "10", "-subj", "/CN=t",
                        "-keyout", f"{d}/k.pem", "-out", f"{d}/c.pem"], check=True, capture_output=True)
        import ssl
        der = ssl.PEM_cert_to_DER_cert(Path(f"{d}/c.pem").read_text())
        days = (checks.cert_not_after(der) - time.time()) / 86400
        self.assertTrue(9 < days <= 10)

    def test_tls_against_local_server(self):
        import shutil
        import ssl
        import subprocess
        if not shutil.which("openssl"):
            self.skipTest("openssl not installed")
        d = tempfile.mkdtemp()
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "5", "-subj", "/CN=t",
                        "-keyout", f"{d}/k.pem", "-out", f"{d}/c.pem"], check=True, capture_output=True)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(f"{d}/c.pem", f"{d}/k.pem")
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            port = httpd.server_address[1]
            r = checks.run(Check("a", "tls", f"127.0.0.1:{port}", warn_days=14))
            self.assertFalse(r.ok)
            self.assertIn("expires in 4 days", r.detail)
            self.assertTrue(checks.run(Check("a", "tls", f"127.0.0.1:{port}", warn_days=2)).ok)
        finally:
            stop(httpd)


def monitor(*cs, **kw) -> tuple[Monitor, list]:
    sent = []
    cfg = Config(checks=list(cs), notifiers=[{"name": "n", "type": "webhook", "url": "x"}], **kw)
    m = Monitor(cfg)
    m.state_file = None
    m.pool = Now()
    notify_send = notify.send

    def capture(n, ev, title="Vitals"):
        sent.append(ev)
    notify.send = capture
    m._restore = lambda: setattr(notify, "send", notify_send)
    return m, sent


class UpDown(unittest.TestCase):
    def tearDown(self):
        if hasattr(self, "m"):
            self.m._restore()

    def test_down_after_fail_after_then_one_recovery(self):
        c = Check("web", "http", "x", fail_after=3)
        self.m, sent = monitor(c)
        t = 1_000_000.0
        self.m.record(c, Result(True), t)
        self.m.record(c, Result(False, "boom"), t + 1)
        self.m.record(c, Result(False, "boom"), t + 2)
        self.assertEqual(sent, [])
        self.m.record(c, Result(False, "boom"), t + 3)
        self.m.record(c, Result(False, "boom"), t + 4)
        self.assertEqual([e["kind"] for e in sent], ["down"])
        self.m.record(c, Result(True), t + 63)
        self.assertEqual([e["kind"] for e in sent], ["down", "up"])
        self.assertEqual(sent[1]["down_for"], 60)
        self.assertEqual(len(self.m.incidents), 1)
        self.assertEqual(self.m.incidents[0]["end"], t + 63)

    def test_maintenance_is_silent_and_not_counted(self):
        c = Check("nas", "http", "x", fail_after=1)
        now = datetime.now()
        self.m, sent = monitor(c, maintenance=[{"start": (now - timedelta(hours=1)).isoformat(),
                                                "end": (now + timedelta(hours=1)).isoformat(), "checks": ["nas"]}])
        self.m.record(c, Result(False, "rebooting"))
        self.m.record(c, Result(True))
        self.assertEqual(sent, [])
        self.assertIsNone(self.m.uptime(self.m.states[c.id], 24))
        self.assertTrue(self.m.incidents[0]["maintenance"])

    def test_quiet_hours_hold_then_digest(self):
        c = Check("web", "http", "x", fail_after=1)
        self.m, sent = monitor(c)
        quiet = [True]
        self.m.quiet = lambda now: quiet[0]
        self.m.record(c, Result(False, "boom"))
        self.assertEqual(sent, [])
        self.assertEqual(len(self.m.held), 1)
        quiet[0] = False
        self.m._flush_held(time.time())
        self.assertEqual(sent[0]["kind"], "digest")
        self.assertEqual(sent[0]["still_down"], ["web"])

    def test_quiet_window_parsing(self):
        self.m, _ = monitor(quiet={"hours": "23:00-07:00"})
        at = lambda h: datetime(2026, 1, 1, h, 30).timestamp()  # noqa: E731
        self.assertTrue(self.m.quiet(at(23)))
        self.assertTrue(self.m.quiet(at(3)))
        self.assertFalse(self.m.quiet(at(12)))

    def test_reminders(self):
        c = Check("web", "http", "x", fail_after=1)
        self.m, sent = monitor(c, remind_every=30)
        self.m.record(c, Result(False, "boom"), 1000.0)
        self.m._remind(1000.0 + 29 * 60)
        self.m._remind(1000.0 + 31 * 60)
        self.assertEqual([e["kind"] for e in sent], ["down", "reminder"])

    def test_notifier_routing(self):
        c = Check("web", "http", "x", fail_after=1, notify=["other"])
        self.m, sent = monitor(c)
        self.m.record(c, Result(False))
        self.assertEqual(sent, [])

    def test_uptime_and_bars(self):
        c = Check("web", "http", "x")
        self.m, _ = monitor(c)
        now = time.time()
        for i in range(10):
            self.m.record(c, Result(i != 0), now)
        st = self.m.states[c.id]
        self.assertEqual(self.m.uptime(st, 24, now), 90.0)
        bars = self.m.bars(st, now)
        self.assertEqual((len(bars), bars[-1], bars[0]), (30, 90.0, None))

    def test_restart_keeps_outage_without_alerting_again(self):
        c = Check("web", "http", "x", fail_after=1)
        self.m, sent = monitor(c)
        self.m.state_file = Path(TMP) / "state-test.json"
        self.m.record(c, Result(False, "boom"))
        self.m.save()
        self.m._restore()
        m2, sent2 = monitor(c)
        self.m = m2
        m2.state_file = Path(TMP) / "state-test.json"
        m2.load()
        m2.record(c, Result(False, "boom"))
        self.assertEqual(sent2, [])
        m2.record(c, Result(True))
        self.assertEqual([e["kind"] for e in sent2], ["up"])
        self.assertIsNotNone(m2.incidents[0]["end"])


class SettFeedTests(unittest.TestCase):
    def test_reads_services_and_node_health(self):
        doc = {"services": [
            {"key": "sonarr@pve:lxc/105", "name": "Sonarr", "host": "media", "app": "sonarr", "category": "Media",
             "status": "down", "error": "no response"},
            {"key": "a@h", "name": "Docs", "app": "manual", "category": "Links", "status": "unknown"},
            {"key": "f@h", "name": "FlareSolverr", "app": "flaresolverr", "category": "Apps", "status": "up"}],
            "nodes": [{"name": "alpha", "health": [{"label": "SMART", "value": "1 failing", "tone": "bad", "detail": "sdb"}]}]}
        Fake.routes = {"/api/status": (200, json.dumps(doc).encode(), {"Content-Type": "application/json"})}
        httpd, base = serve(Fake)
        try:
            feed = SettFeed({"url": base, "exclude": ["flaresolverr"]})
            got = {c.name: r for c, r in feed.poll()}
        finally:
            stop(httpd)
        self.assertEqual(sorted(got), ["Sett", "Sonarr (media)", "alpha health"])
        self.assertFalse(got["Sonarr (media)"].ok)
        self.assertEqual(got["alpha health"].detail, "SMART: 1 failing (sdb)")

    def test_restarting_sett_does_not_drop_services(self):
        up = {"services": [{"key": "p@h", "name": "Paperless", "status": "down"}], "nodes": []}
        restarting = {"services": [{"key": "p@h", "name": "Paperless", "status": "unknown"}], "nodes": []}
        empty = {"services": [], "nodes": []}
        feed = SettFeed({"url": "http://x"})
        for doc in (up, restarting, empty):
            feed.fetch = lambda d=doc: d
            feed.poll()
            self.assertIn("sett:p@h", {c.id for c in feed.checks()})

    def test_unreachable_sett_is_one_failure(self):
        feed = SettFeed({"url": f"http://127.0.0.1:{free_port()}"})
        [(c, r)] = feed.poll()
        self.assertEqual((c.name, r.ok), ("Sett", False))

    def test_sett_401_says_what_to_do(self):
        Fake.routes = {"/api/status": (401, b"{}", {})}
        httpd, base = serve(Fake)
        try:
            [(c, r)] = SettFeed({"url": base}).poll()
        finally:
            stop(httpd)
        self.assertIn("api_tokens", r.detail)


class Notifiers(unittest.TestCase):
    def setUp(self):
        Fake.posts = []
        self.httpd, self.base = serve(Fake)

    def tearDown(self):
        stop(self.httpd)

    def test_ntfy_gotify_discord_webhook(self):
        ev = {"kind": "down", "check": "Plex", "detail": "HTTP 502", "at": 0}
        notify.ntfy({"url": f"{self.base}/alerts", "token": "tk"}, ev, "Lab")
        notify.gotify({"url": self.base, "token": "gk"}, ev, "Lab")
        notify.discord({"url": f"{self.base}/discord"}, ev, "Lab")
        notify.webhook({"url": f"{self.base}/hook"}, ev, "Lab")
        (p1, h1, b1), (p2, h2, b2), (p3, _, b3), (p4, _, b4) = Fake.posts
        self.assertEqual((p1, h1["Priority"], h1["Authorization"]), ("/alerts", "5", "Bearer tk"))
        self.assertTrue(h1["Title"].startswith("=?UTF-8?B?"))    # the emoji is not Latin-1
        self.assertIn(b"HTTP 502", b1)
        self.assertEqual((p2, h2["X-Gotify-Key"], json.loads(b2)["priority"]), ("/message", "gk", 5))
        self.assertIn("Plex is down", json.loads(b3)["content"])
        self.assertEqual(json.loads(b4)["check"], "Plex")

    def test_messages(self):
        self.assertEqual(notify.message({"kind": "up", "check": "X", "down_for": 3720}, "T")[1], "X is back after 1h 2m.")
        self.assertEqual(fmt_duration(90061), "1 day 1h")


class Page(unittest.TestCase):
    def setUp(self):
        a = Check("Public", "http", "http://10.0.0.5/", fail_after=1)
        b = Check("Secret", "http", "http://10.0.0.6/", public=False)
        self.m, _ = monitor(a, b, tokens={"me": "tok"})
        self.m.record(a, Result(False, "connection refused at 10.0.0.5"))
        self.httpd, self.base = serve(make_handler(self.m))

    def tearDown(self):
        stop(self.httpd)
        self.m._restore()

    def get(self, path, headers=None):
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(urllib.request.Request(self.base + path, headers=headers or {}), timeout=5) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def test_token_required_by_default(self):
        self.assertEqual(self.get("/api/status")[0], 401)
        self.assertEqual(self.get("/")[0], 401)
        self.assertEqual(self.get("/healthz")[0], 200)
        status, _, body = self.get("/api/status", {"Authorization": "Bearer tok"})
        names = [c["name"] for c in json.loads(body)["checks"]]
        self.assertEqual((status, sorted(names)), (200, ["Public", "Secret"]))

    def test_token_link_becomes_cookie(self):
        status, headers, _ = self.get("/?token=tok")
        self.assertEqual(status, 302)
        cookie = headers["Set-Cookie"].split(";")[0]
        self.assertEqual(self.get("/", {"Cookie": cookie})[0], 200)

    def test_public_page_hides_private_checks_and_details(self):
        self.m.cfg.public_status = True
        d = json.loads(self.get("/api/status")[2])
        self.assertEqual([c["name"] for c in d["checks"]], ["Public"])
        self.assertNotIn("detail", d["checks"][0])
        self.assertNotIn("detail", d["incidents"][0])
        self.assertNotIn("10.0.0.5", json.dumps(d))


LINUX = {"name": "pve1", "os": "linux", "uptime": 90000, "memory": {"used_pct": 40.0},
         "disks": [{"mount": "/", "used_pct": 50.0, "free": 50 * 2**30}, {"mount": "/mnt/tank", "used_pct": 93.0, "free": 2**30}],
         "temps": [{"sensor": "coretemp", "celsius": 61.0}], "failed_services": ["smartd.service"], "updates": 3,
         "reboot_required": True}
WINDOWS = {"name": "KKINGD01", "os": "windows", "memory": {"used_pct": 55.0},
           "disks": [{"mount": "C:", "used_pct": 70.0, "free": 100 * 2**30}], "temps": [], "failed_services": [],
           "updates": 12, "reboot_required": False, "defender": {"realtime": False, "antivirus": True, "signature_age_days": 1}}


class Agents(unittest.TestCase):
    def test_evaluate_linux(self):
        from vitals import agents
        got = {c.name: r for c, r in agents.evaluate("pve1", LINUX, agents.host_conf({}, "pve1"))}
        self.assertTrue(got["pve1"].ok)
        self.assertFalse(got["pve1 · disk"].ok)
        self.assertEqual(got["pve1 · disk"].detail, "/mnt/tank 93% (1.0 GB free)")
        self.assertTrue(got["pve1 · temperature"].ok)
        self.assertEqual(got["pve1 · services"].detail, "failed: smartd.service")
        self.assertNotIn("pve1 · updates", got)     # off unless updates_above is set
        self.assertEqual(agents.summary(LINUX), "/mnt/tank 93% · RAM 40% · 61°C · 3 updates · reboot pending · up 1d 1h")

    def test_overrides_and_ignores(self):
        from vitals import agents
        conf = agents.host_conf({"disk_above": 80, "ignore_services": ["smartd.service"],
                                 "hosts": {"pve1": {"disk_above": 95}}}, "pve1")
        got = {c.name: r for c, r in agents.evaluate("pve1", LINUX, conf)}
        self.assertTrue(got["pve1 · disk"].ok)
        self.assertTrue(got["pve1 · services"].ok)

    def test_windows_defender_and_updates(self):
        from vitals import agents
        got = {c.name: r for c, r in agents.evaluate("KKINGD01", WINDOWS, agents.host_conf({"updates_above": 10}, "KKINGD01"))}
        self.assertFalse(got["KKINGD01 · defender"].ok)
        self.assertFalse(got["KKINGD01 · updates"].ok)
        self.assertNotIn("KKINGD01 · temperature", got)

    def test_windows_one_item_lists_and_odd_values(self):
        """What Windows PowerShell 5.1 sends for a PC with one disk and one crashed service."""
        from vitals import agents
        odd = {"name": "KKINGD01", "os": "windows", "disks": {"mount": "C:", "used_pct": "96.2", "free": 38900000000},
               "failed_services": "Spooler", "temps": None, "memory": {"used_pct": 40}, "updates": "4",
               "defender": "unknown"}
        doc = agents.normalize(odd)
        got = {c.name: r for c, r in agents.evaluate("KKINGD01", doc, agents.host_conf({}, "KKINGD01"))}
        self.assertEqual(got["KKINGD01 · disk"].detail, "C: 96% (36.2 GB free)")
        self.assertEqual(got["KKINGD01 · services"].detail, "failed: Spooler")
        self.assertTrue(agents.summary(doc).startswith("C: 96% · RAM 40% · 4 updates"))
        agents.normalize({"name": "x", "disks": ["garbage", {"mount": None}], "temps": [{"celsius": "hot"}]})

    def test_disk_forecast(self):
        from vitals import agents
        t0 = 1_000_000.0
        rising = [[t0 + h * 3600, 80 + h * 0.1] for h in range(48)]          # +2.4% a day from 84.7%
        self.assertAlmostEqual(agents.forecast(rising, t0 + 47 * 3600), (100 - 84.7) / 2.4, places=1)
        self.assertIsNone(agents.forecast([[t0 + h * 3600, 70.0] for h in range(48)], t0 + 47 * 3600))   # flat
        self.assertIsNone(agents.forecast(rising[:3], t0 + 2 * 3600))                                  # too little

    def test_filling_disk_alerts_before_the_limit(self):
        m, sent = monitor()
        try:
            t0 = 1_000_000.0
            for h in range(30):   # a disk at 60% gaining 2% an hour: full in well under a day
                m.agent_report({"name": "pve3", "os": "linux", "disks": [{"mount": "/tank", "used_pct": 60 + 2 * h, "free": 1}]},
                               now=t0 + h * 3600)
            disk = [e for e in sent if e["check"] == "pve3 · disk"]
            self.assertEqual(disk[0]["kind"], "down")
            self.assertIn("/tank full in ~", disk[0]["detail"])
            self.assertIn("/tank full in ~", m.hosts["pve3"]["summary"])
        finally:
            m._restore()

    def test_names_are_checked(self):
        from vitals import agents
        self.assertEqual(agents.clean_name(" pve-1.lan "), "pve-1.lan")
        self.assertIsNone(agents.clean_name("x; rm -rf /"))
        self.assertIsNone(agents.clean_name(""))

    def test_heartbeat_goes_down_and_wording(self):
        self.m, sent = monitor(agents={"every": 60, "missed": 3})
        try:
            self.m.agent_report(dict(LINUX, failed_services=[], disks=[]), now=1000.0)
            self.m._agent_heartbeats(1000.0 + 120)
            self.assertEqual(sent, [])
            self.m._agent_heartbeats(1000.0 + 200)
            self.assertEqual([e["about"] for e in sent], ["host"])
            self.assertEqual(self.m.incidents[-1]["about"], "host")
            self.assertEqual(notify.message(sent[0], "T")[0], "🔴 pve1 stopped reporting")
            self.m.agent_report(dict(LINUX, failed_services=[], disks=[]), now=1000.0 + 260)
            self.assertEqual(notify.message(sent[-1], "T")[0], "🟢 pve1 is reporting again")
        finally:
            self.m._restore()

    def test_problem_wording(self):
        ev = {"kind": "down", "check": "pve1 · disk", "detail": "/mnt/tank 93%", "about": "problem"}
        self.assertEqual(notify.message(ev, "T")[0], "🔴 pve1 · disk: /mnt/tank 93%")

    def test_silent_host_is_forgotten(self):
        from vitals import agents
        self.m, _ = monitor()
        try:
            self.m.agent_report(LINUX, now=1000.0)
            self.m._agent_heartbeats(1000.0 + agents.FORGET_AFTER + 1)
            self.assertEqual(self.m.hosts, {})
            self.assertFalse(any(k.startswith("agent:") for k in self.m.states))
        finally:
            self.m._restore()


class SitesAndRouting(unittest.TestCase):
    def test_site_down_only_when_members_go_down_together(self):
        from vitals.monitor import SITE_EVERY
        pc, bhd = Check("KKINGD01", "tcp", "x", fail_after=1), Check("BHD01", "tcp", "x", fail_after=1)
        self.m, sent = monitor(pc, bhd, sites=[{"name": "Office", "address": "203.0.113.7",
                                                "members": ["config:KKINGD01", "BHD01"]}])
        self.m.cfg.notifiers = [{"name": "discord", "type": "discord", "url": "x", "events": ["site"]}]
        try:
            t = 1000.0
            self.m.record(pc, Result(False), t)            # one PC rebooting: not a site outage
            for i in range(3):
                self.m._sites(t + 20 * (i + 1))
            self.assertEqual([e for e in sent if e["about"] == "site"], [])
            self.assertEqual([a["check"] for a in self.m.activity], ["KKINGD01"])
            self.assertEqual(self.m.activity[0]["sent"], [])   # logged, not sent to Discord
            self.m.record(bhd, Result(False), t + 70)
            for i in range(2):
                self.m._sites(t + 80 + 20 * i)
            [ev] = [e for e in sent if e["about"] == "site"]
            self.assertEqual((ev["kind"], ev["check"], ev["address"]), ("down", "Office", "203.0.113.7"))
            self.assertEqual(notify.message(ev, "T", {"down": "{name} at {address} is DOWN"})[0],
                             "Office at 203.0.113.7 is DOWN")
        finally:
            self.m._restore()

    def test_wants(self):
        from vitals.monitor import wants
        ev = {"kind": "down", "about": "host", "check": "KKINGD01", "id": "agent:KKINGD01/host", "group": "Hosts"}
        self.assertTrue(wants({}, ev))                                  # default: everything
        self.assertFalse(wants({"events": ["site"]}, ev))
        self.assertFalse(wants({"enabled": False}, ev))
        self.assertTrue(wants({"only": ["KKINGD01"]}, {**ev, "id": "agent:KKINGD01/disk", "check": "KKINGD01 · disk",
                                                       "about": "problem"}))
        self.assertFalse(wants({"events": ["host"]}, {**ev, "kind": "reminder"}))
        self.assertTrue(wants({"events": ["site"]}, {"kind": "test"}))

    def test_mute_logs_without_sending(self):
        c = Check("web", "http", "x", fail_after=1)
        self.m, sent = monitor(c)
        self.m.cfg.muted = {c.id}
        try:
            self.m.record(c, Result(False))
            self.assertEqual(sent, [])
            self.assertTrue(self.m.activity[-1]["muted"])
        finally:
            self.m._restore()

    def test_problem_needs_two_good_readings_to_recover(self):
        c = Check("pc · disk", "agent", "pc", fail_after=1, recover_after=2)
        self.m, sent = monitor(c)
        try:
            self.m.record(c, Result(False, "F: 96%"), 1.0)
            self.m.record(c, Result(True), 2.0)
            self.assertEqual(self.m.states[c.id].status, "down")
            self.m.record(c, Result(False, "F: 96%"), 3.0)
            self.m.record(c, Result(True), 4.0)
            self.m.record(c, Result(True), 5.0)
            self.assertEqual([e["kind"] for e in sent], ["down", "up"])
        finally:
            self.m._restore()


class SettingsDoc(unittest.TestCase):
    def test_clean_and_masked_secrets(self):
        from vitals import settings as S
        old = {"notifiers": [{"name": "discord", "type": "discord", "url": "https://discord.com/api/webhooks/1/abcdef"}]}
        view = S.notifier_view(old["notifiers"][0])
        self.assertNotIn("abcdef", view["url"][:-4])
        doc = S.clean({"notifiers": [{**view, "events": ["site"], "format": {"down": "{name} at {address} is DOWN"}}],
                       "sites": [{"name": "HomeLab", "members": ["a", "b", "c"], "count": 2}],
                       "agents": {"disk_above": "95", "hosts": {"KKINGD01": {"ignore_mounts": "F:, G:"}}},
                       "quiet": {"hours": "23:00-07:00"}}, old)
        self.assertEqual(doc["notifiers"][0]["url"], "https://discord.com/api/webhooks/1/abcdef")
        self.assertEqual(doc["sites"][0]["count"], 2)
        self.assertEqual(doc["agents"]["hosts"]["KKINGD01"]["ignore_mounts"], ["F:", "G:"])
        for bad in ({"quiet": {"hours": "late"}},
                    {"notifiers": [{"name": "x", "type": "discord", "url": "ftp://x"}]},
                    {"notifiers": [{"name": "x", "type": "discord", "url": "https://x", "format": {"down": "{oops}"}}]},
                    {"sites": [{"name": "S", "members": ["a"], "count": 5}]},
                    {"notifiers": [{"name": "d", "type": "discord", "url": "https://discord.com/channels/1/2"}]}):
            with self.assertRaises(S.Invalid):
                S.clean(bad, {})


class AgentHttp(unittest.TestCase):
    def setUp(self):
        self.m, self.sent = monitor(agents={"token": "agent-tok"}, tokens={"me": "page"})
        self.httpd, self.base = serve(make_handler(self.m))

    def tearDown(self):
        stop(self.httpd)
        self.m._restore()

    def post(self, doc, token):
        r = urllib.request.Request(self.base + "/api/report", data=json.dumps(doc).encode(), method="POST",
                                   headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(r, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, None

    def test_report_needs_the_agent_token(self):
        self.assertEqual(self.post(WINDOWS, "page")[0], 401)
        from vitals.agents import AGENT_VERSION
        self.assertEqual(self.post(WINDOWS, "agent-tok"), (200, {"ok": True, "name": "KKINGD01", "agent_version": AGENT_VERSION}))
        self.assertIn("KKINGD01", self.m.hosts)
        self.assertEqual(self.post({"name": "bad name!"}, "agent-tok")[0], 400)

    def test_installers_are_filled_in(self):
        with self.assertRaises(urllib.error.HTTPError):
            urllib.request.urlopen(self.base + "/install.ps1?token=wrong", timeout=5)
        with urllib.request.urlopen(self.base + "/install.ps1?token=agent-tok", timeout=5) as r:
            body = r.read().decode()
        self.assertIn(f"$Server = '{self.base}'", body)
        self.assertIn("$Token = 'agent-tok'", body)
        self.assertNotIn("__", body.split("$Server")[1][:40])
        with urllib.request.urlopen(self.base + "/agent.py?token=agent-tok", timeout=5) as r:
            self.assertIn(b"def report", r.read())


class SettingsApi(unittest.TestCase):
    def setUp(self):
        from vitals import settings as S
        self.path = Path(TMP) / "settings.json"
        if self.path.exists():
            self.path.unlink()
        self.m, self.sent = monitor(Check("Plex", "tcp", "x"), tokens={"me": "tok"})
        self.httpd, self.base = serve(make_handler(self.m))
        self.S = S

    def tearDown(self):
        stop(self.httpd)
        self.m._restore()
        if self.path.exists():
            self.path.unlink()

    def call(self, method, path, body=None, headers=None):
        h = {"Authorization": "Bearer tok", "Content-Type": "application/json", **(headers or {})}
        r = urllib.request.Request(self.base + path, data=None if body is None else json.dumps(body).encode(),
                                   method=method, headers=h)
        try:
            with urllib.request.urlopen(r, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")

    def test_needs_token_and_same_origin(self):
        self.assertEqual(self.call("GET", "/api/settings", headers={"Authorization": ""})[0], 401)
        self.assertEqual(self.call("PUT", "/api/settings", {}, {"Origin": "http://evil.example"})[0], 403)
        self.assertEqual(self.call("PUT", "/api/settings", {}, {"Content-Type": "text/plain"})[0], 403)

    def test_save_applies_straight_away(self):
        status, view = self.call("PUT", "/api/settings", {
            "notifiers": [{"name": "discord", "type": "discord", "url": "https://discord.com/api/webhooks/1/secret",
                           "events": ["site"]}],
            "sites": [{"name": "HomeLab", "members": ["config:Plex"], "count": 1}], "muted": ["config:Plex"]})
        self.assertEqual(status, 200)
        self.assertEqual([n["name"] for n in self.m.cfg.notifiers], ["discord"])   # reloaded from files + settings
        self.assertEqual(self.m.cfg.muted, {"config:Plex"})
        self.assertEqual([s["name"] for s in view["sites"]], ["HomeLab"])
        self.assertNotIn("secret", json.dumps(view))                     # never sent back in full
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_bad_input_is_explained(self):
        status, body = self.call("PUT", "/api/settings", {"quiet": {"hours": "bedtime"}})
        self.assertEqual(status, 422)
        self.assertIn("23:00-07:00", body["error"])

    def test_activity(self):
        self.m.record(Check("Plex", "tcp", "x", fail_after=1), Result(False, "refused"))
        status, items = self.call("GET", "/api/activity")
        self.assertEqual((status, items[0]["check"]), (200, "Plex"))


class CheckIns(unittest.TestCase):
    def test_missed_check_in_alerts_and_ping_recovers(self):
        c = Check("PBS backup", "push", "", every=86400, fail_after=1)
        self.m, sent = monitor(c)
        self.m.cfg.push_secret = "s"
        try:
            t0 = self.m.started
            token = self.m.push_token(c)
            self.assertEqual(token, self.m.push_token(c))          # stable
            self.assertIsNone(self.m.push("wrong", now=t0))
            self.assertEqual(self.m.push(token, now=t0 + 10), "PBS backup")
            self.m.tick(t0 + 86400)                                 # within the grace period
            self.assertEqual(sent, [])
            self.m.tick(t0 + 90100)                                 # 10s past every + 1h grace
            self.assertEqual([(e["kind"], e["detail"]) for e in sent], [("down", "no check-in for 1 day 1h")])
            self.m.push(token, now=t0 + 90200)
            self.assertEqual(sent[-1]["kind"], "up")
            self.m.push(token, ok=False, msg="pbs: datastore full", now=t0 + 90210)
            self.assertEqual((sent[-1]["kind"], sent[-1]["detail"]), ("down", "pbs: datastore full"))
        finally:
            self.m._restore()

    def test_push_endpoint(self):
        c = Check("TheTree snapshot", "push", "", every=3600, fail_after=1)
        m, _ = monitor(c)
        m.cfg.push_secret = "s"
        httpd, base = serve(make_handler(m))
        try:
            with urllib.request.urlopen(f"{base}/api/push/{m.push_token(c)}", timeout=5) as r:
                self.assertEqual(r.read(), b"ok: TheTree snapshot\n")
            with self.assertRaises(urllib.error.HTTPError):
                urllib.request.urlopen(f"{base}/api/push/nope", timeout=5)
            self.assertEqual(m.states[c.id].status, "up")
            self.assertIsNotNone(next(r for r in m.status(True)["checks"] if r["id"] == c.id)["last_ping"])
        finally:
            stop(httpd)
            m._restore()


class KumaImport(unittest.TestCase):
    def make_db(self):
        import sqlite3
        f = Path(tempfile.mkdtemp()) / "kuma.db"
        con = sqlite3.connect(f)
        con.execute("""CREATE TABLE monitor (id INTEGER PRIMARY KEY, name TEXT, active INTEGER, interval INTEGER, url TEXT,
                       type TEXT, hostname TEXT, port INTEGER, keyword TEXT, maxretries INTEGER, upside_down INTEGER,
                       push_token TEXT, parent INTEGER, invert_keyword INTEGER)""")
        rows = [(1, "Media", 1, 60, None, "group", None, None, None, 0, 0, None, None, 0),
                (2, "Plex", 1, 30, "http://10.0.0.130:32400/web", "http", None, None, None, 2, 0, None, 1, 0),
                (3, "Sonarr", 1, 60, "http://10.0.0.130:8989", "keyword", None, None, "Sonarr", 0, 0, None, 1, 0),
                (4, "NAS SSH", 1, 120, None, "port", "10.0.0.123", 2222, None, 1, 0, None, None, 0),
                (5, "PBS nightly", 1, 86400, None, "push", None, None, None, 0, 0, "kumaPushTok1", None, 0),
                (6, "Postgres", 1, 60, None, "postgres", None, None, None, 0, 0, None, None, 0),
                (7, "Old thing", 0, 60, "http://x", "http", None, None, None, 0, 0, None, None, 0)]
        con.executemany("INSERT INTO monitor VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        con.commit()
        con.close()
        return f

    def test_convert(self):
        from vitals import kuma
        checks, notes = kuma.convert(kuma.read(str(self.make_db())))
        got = {c["name"]: c for c in checks}
        self.assertEqual(sorted(got), ["NAS SSH", "PBS nightly", "Plex", "Sonarr"])
        self.assertEqual((got["Plex"]["group"], got["Plex"]["every"], got["Plex"]["fail_after"]), ("Media", 30, 3))
        self.assertEqual(got["Sonarr"]["contains"], "Sonarr")
        self.assertEqual(got["NAS SSH"]["target"], "10.0.0.123:2222")
        self.assertEqual((got["PBS nightly"]["type"], got["PBS nightly"]["token"]), ("push", "kumaPushTok1"))
        self.assertTrue(any("Postgres" in n for n in notes) and any("Old thing" in n for n in notes))

    def test_import_keeps_push_urls(self):
        from vitals import config, kuma
        from vitals import settings as S
        if S.path().exists():
            S.path().unlink()
        os.environ["VITALS_CONFIG"] = str(Path(TMP) / "none.toml")
        try:
            self.assertEqual(kuma.main([str(self.make_db())]), 0)
            self.assertEqual(kuma.main([str(self.make_db())]), 0)      # twice: nothing duplicated
            cfg = config.load()
        finally:
            del os.environ["VITALS_CONFIG"]
            S.path().unlink()
        self.assertEqual(sum(c.name == "Plex" for c in cfg.checks), 1)
        m = Monitor(cfg)
        push = next(c for c in cfg.checks if c.type == "push")
        self.assertEqual(m.push_token(push), "kumaPushTok1")
        self.assertEqual(m.push("kumaPushTok1"), "PBS nightly")


class Weekly(unittest.TestCase):
    def test_monday_morning_only_to_notifiers_that_ask(self):
        from vitals.monitor import last_monday_9
        c = Check("Plex", "tcp", "x", fail_after=1)
        m, sent = monitor(c, sites=[{"name": "HomeLab", "members": ["Plex"]}])
        m.cfg.notifiers = [{"name": "phone", "type": "webhook", "url": "x", "events": ["weekly"]},
                           {"name": "discord", "type": "discord", "url": "x", "events": ["site"]}]
        try:
            mon = datetime(2026, 11, 2, 9, 0).timestamp()          # a Monday, 09:00
            self.assertEqual(last_monday_9(mon + 3600), mon)
            self.assertEqual(last_monday_9(mon - 60), mon - 7 * 86400)
            m.record(c, Result(False, "refused"), mon - 86400)
            m.record(c, Result(True), mon - 86400 + 600)
            m._weekly(mon - 3600)                                   # first run: remember, don't send
            self.assertEqual(sent, [])
            m._weekly(mon + 60)
            [ev] = [e for e in sent if e["kind"] == "weekly"]
            self.assertIn("Plex 1x, 10m", " ".join(ev["lines"]))
            subject, body = notify.message(ev, "Lab")
            self.assertTrue(subject.startswith("Lab: the week in review"))
            m._weekly(mon + 120)                                    # once per week
            self.assertEqual(len([e for e in sent if e["kind"] == "weekly"]), 1)
            m._weekly(mon + 7 * 86400 + 13 * 3600)                  # Vitals was down: skipped, not late
            self.assertEqual(len([e for e in sent if e["kind"] == "weekly"]), 1)
        finally:
            m._restore()


class Acknowledge(unittest.TestCase):
    def test_ack_stops_reminders_until_recovery(self):
        c = Check("web", "http", "x", fail_after=1)
        m, sent = monitor(c, remind_every=30)
        try:
            m.record(c, Result(False), 1000.0)
            self.assertTrue(m.acknowledge(c.id, "page", 1100.0))
            m._remind(1000.0 + 31 * 60)
            self.assertEqual([e["kind"] for e in sent], ["down"])
            self.assertTrue(next(r for r in m.status(True)["checks"] if r["id"] == c.id)["acked"])
            m.record(c, Result(True), 3000.0)
            self.assertFalse(m.acknowledge(c.id))                   # nothing down to acknowledge
            m.record(c, Result(False), 4000.0)
            m._remind(4000.0 + 31 * 60)                              # a new outage reminds again
            self.assertEqual([e["kind"] for e in sent], ["down", "up", "down", "reminder"])
        finally:
            m._restore()


class Updates(unittest.TestCase):
    def test_status(self):
        from vitals import updates
        updates.latest.clear()
        os.environ["VITALS_BUILD"] = "aaaaaaa1111"
        try:
            self.assertIsNone(updates.status())                                   # nothing known yet
            updates.latest.update(sha="aaaaaaa1111", message="x", date="d")
            self.assertIsNone(updates.status())                                   # up to date
            updates.latest.update(sha="bbbbbbb2222", message="weekly summary", date="d")
            self.assertEqual(updates.status()["latest"], "bbbbbbb")
        finally:
            del os.environ["VITALS_BUILD"]
            updates.latest.clear()


class Maintenance(unittest.TestCase):
    def test_daily_and_overnight_windows(self):
        from vitals.monitor import _in_daily_window
        at = lambda d, h, mi: datetime(2026, 11, d, h, mi).timestamp()   # noqa: E731 (Nov 2 2026 is a Monday)
        self.assertTrue(_in_daily_window(at(2, 3, 10), [], "03:00", "03:30"))
        self.assertFalse(_in_daily_window(at(2, 3, 30), [], "03:00", "03:30"))
        self.assertFalse(_in_daily_window(at(2, 3, 10), ["sun"], "03:00", "03:30"))
        self.assertTrue(_in_daily_window(at(1, 23, 45), ["sun"], "23:30", "01:00"))     # Sunday night...
        self.assertTrue(_in_daily_window(at(2, 0, 30), ["sun"], "23:30", "01:00"))      # ...into Monday
        self.assertFalse(_in_daily_window(at(3, 0, 30), ["sun"], "23:30", "01:00"))

    def test_window_silences_matching_checks_only(self):
        a, b = Check("PBS", "tcp", "x", group="Backups"), Check("Plex", "tcp", "x")
        m, _ = monitor(a, b, maintenance=[{"from": "00:00", "to": "23:59", "checks": ["Backups"]}])
        try:
            now = datetime(2026, 11, 2, 12, 0).timestamp()
            self.assertTrue(m.in_maintenance(a, now))
            self.assertFalse(m.in_maintenance(b, now))
        finally:
            m._restore()

    def test_settings_validate_windows(self):
        from vitals import settings as S
        doc = S.clean({"maintenance": [{"name": "Backups", "days": ["mon", "xyz"], "from": "03:00", "to": "03:30"}]}, {})
        self.assertEqual(doc["maintenance"][0]["days"], ["mon"])
        with self.assertRaises(S.Invalid):
            S.clean({"maintenance": [{"from": "3am", "to": "04:00"}]}, {})


class AgentFiles(unittest.TestCase):
    def test_versions_agree(self):
        """The server offers AGENT_VERSION; both agents must say the same, or they'd update forever."""
        from vitals.agents import AGENT_VERSION
        here = Path(__file__).parent.parent / "vitals"
        self.assertIn(f'VERSION = "{AGENT_VERSION}"', (here / "agent.py").read_text())
        self.assertIn(f"$Version = '{AGENT_VERSION}'", (here / "agent.ps1").read_text())

    def test_powershell_scripts_are_balanced(self):
        """No PowerShell here to parse them, so at least: every brace, bracket and paren
        closes, outside strings and comments, and every string ends."""
        here = Path(__file__).parent.parent / "vitals"
        for f in (here / "agent.ps1", here / "tray.ps1", here / "install" / "install.ps1"):
            text, stack, i, line = f.read_text(), [], 0, 1
            pairs = {")": "(", "}": "{", "]": "["}
            while i < len(text):
                ch = text[i]
                if ch == "\n":
                    line += 1
                elif ch == "#":
                    i = text.find("\n", i) - 1 if "\n" in text[i:] else len(text)
                elif ch == "'":
                    j = i + 1
                    while True:
                        j = text.index("'", j)          # raises if the string never ends
                        if text[j + 1:j + 2] == "'":
                            j += 2
                            continue
                        break
                    line += text[i:j].count("\n")
                    i = j
                elif ch == '"':
                    j = i + 1
                    while text[j] != '"':
                        j += 2 if text[j] == "`" else 1
                    line += text[i:j].count("\n")
                    i = j
                elif ch in "({[":
                    stack.append((ch, line))
                elif ch in ")}]":
                    self.assertTrue(stack and stack[-1][0] == pairs[ch], f"{f.name}:{line}: unexpected {ch}")
                    stack.pop()
                i += 1
            self.assertEqual(stack, [], f"{f.name}: unclosed {stack[-1:]}")

    def test_linux_agent_updates_itself(self):
        """Serve a newer agent.py; the old one downloads it, checks it, and replaces itself."""
        import importlib.util
        import shutil
        d = Path(tempfile.mkdtemp())
        src = Path(__file__).parent.parent / "vitals" / "agent.py"
        shutil.copy(src, d / "agent.py")
        newer = src.read_text().replace(f'VERSION = "', 'VERSION = "9.9.9" #', 1)
        Fake.routes = {"/agent.py": (200, newer.encode(), {})}
        httpd, base = serve(Fake)
        spec = importlib.util.spec_from_file_location("agent_copy", d / "agent.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        execs = []
        real_execv = mod.os.execv
        mod.os.execv = lambda *a: execs.append(a)   # don't really restart the test runner
        try:
            self.assertTrue(mod.update(base, "tok", "9.9.9"))
            self.assertIn('VERSION = "9.9.9"', (d / "agent.py").read_text())
            self.assertEqual(len(execs), 1)
            Fake.routes = {"/agent.py": (200, b"this is not python(", {})}
            self.assertFalse(mod.update(base, "tok", "9.9.9"))   # a broken download changes nothing
            self.assertIn('VERSION = "9.9.9"', (d / "agent.py").read_text())
        finally:
            stop(httpd)
            mod.os.execv = real_execv


class FirstRun(unittest.TestCase):
    def test_tokens_made_once_and_kept(self):
        from vitals import settings as S
        f = Path(TMP) / "tokens.json"
        if f.exists():
            f.unlink()
        a, b = Config(), Config()
        made = S.ensure_tokens(a)
        self.assertEqual(set(made), {"page", "agent"})
        self.assertEqual(f.stat().st_mode & 0o777, 0o600)
        S.ensure_tokens(b)
        self.assertEqual((a.tokens, a.agents["token"]), (b.tokens, b.agents["token"]))   # same after a restart
        c = Config(tokens={"me": "mine"}, agents={"token": "theirs"})
        self.assertEqual(S.ensure_tokens(c), {})                                         # config wins
        self.assertEqual((c.tokens, c.agents["token"]), ({"me": "mine"}, "theirs"))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


if __name__ == "__main__":
    unittest.main()
