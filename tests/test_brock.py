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

TMP = tempfile.mkdtemp(prefix="brock-test-")
os.environ["BROCK_DATA"] = TMP

from brock import checks, config, notify  # noqa: E402
from brock.checks import Result  # noqa: E402
from brock.config import Check, Config  # noqa: E402
from brock.monitor import Monitor, fmt_duration  # noqa: E402
from brock.server import make_handler  # noqa: E402
from brock.sett import SettFeed  # noqa: E402


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
        (d / "brock.toml").write_text('''
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
        os.environ.update(BROCK_CONFIG=str(d / "brock.toml"), BROCK_SECRETS=str(d / "secrets.toml"))
        try:
            cfg = config.load()
        finally:
            del os.environ["BROCK_CONFIG"], os.environ["BROCK_SECRETS"]
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

    def capture(n, ev, title="Brock"):
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
        from brock import agents
        got = {c.name: r for c, r in agents.evaluate("pve1", LINUX, agents.host_conf({}, "pve1"))}
        self.assertTrue(got["pve1"].ok)
        self.assertFalse(got["pve1 · disk"].ok)
        self.assertEqual(got["pve1 · disk"].detail, "/mnt/tank 93% (1.0 GB free)")
        self.assertTrue(got["pve1 · temperature"].ok)
        self.assertEqual(got["pve1 · services"].detail, "failed: smartd.service")
        self.assertNotIn("pve1 · updates", got)     # off unless updates_above is set
        self.assertEqual(agents.summary(LINUX), "/mnt/tank 93% · RAM 40% · 61°C · 3 updates · reboot pending · up 1d 1h")

    def test_overrides_and_ignores(self):
        from brock import agents
        conf = agents.host_conf({"disk_above": 80, "ignore_services": ["smartd.service"],
                                 "hosts": {"pve1": {"disk_above": 95}}}, "pve1")
        got = {c.name: r for c, r in agents.evaluate("pve1", LINUX, conf)}
        self.assertTrue(got["pve1 · disk"].ok)
        self.assertTrue(got["pve1 · services"].ok)

    def test_windows_defender_and_updates(self):
        from brock import agents
        got = {c.name: r for c, r in agents.evaluate("KKINGD01", WINDOWS, agents.host_conf({"updates_above": 10}, "KKINGD01"))}
        self.assertFalse(got["KKINGD01 · defender"].ok)
        self.assertFalse(got["KKINGD01 · updates"].ok)
        self.assertNotIn("KKINGD01 · temperature", got)

    def test_names_are_checked(self):
        from brock import agents
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
        from brock import agents
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
        from brock.monitor import SITE_EVERY
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
        from brock.monitor import wants
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
        from brock import settings as S
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
                    {"sites": [{"name": "S", "members": ["a"], "count": 5}]}):
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
        self.assertEqual(self.post(WINDOWS, "agent-tok"), (200, {"ok": True, "name": "KKINGD01"}))
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
        from brock import settings as S
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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


if __name__ == "__main__":
    unittest.main()
