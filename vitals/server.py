"""HTTP: the status page, /api/status and /healthz.

Without public_status, the page and the API need a token from [tokens]:
`Authorization: Bearer <token>`, or open the page once as /?token=<token>
and a cookie remembers it. With public_status = true anyone can see the
page, but only checks marked public, and without targets or error details.
"""
from __future__ import annotations

import hmac
import json
import logging
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import agents, config, notify, settings
from .monitor import Monitor

log = logging.getLogger(__name__)
WEB = Path(__file__).parent / "web"
HERE = Path(__file__).parent
# Agent files, served to machines that present the agent token.
AGENT_FILES = {"/agent.py": (HERE / "agent.py", "text/x-python"), "/agent.ps1": (HERE / "agent.ps1", "text/plain"),
               "/install.sh": (HERE / "install" / "install.sh", "text/x-shellscript"),
               "/install.ps1": (HERE / "install" / "install.ps1", "text/plain"),
               "/tray.ps1": (HERE / "tray.ps1", "text/plain")}
MAX_REPORT = 256 * 1024
MAX_SETTINGS = 512 * 1024
PAGE_CSP = {"Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                                       "script-src 'self' 'unsafe-inline'; img-src 'self' data:"}
COOKIE = "vitals_token"
OLD_COOKIES = ("brock_token",)   # still accepted: signed in before the rename


def make_handler(mon: Monitor):
    class Handler(BaseHTTPRequestHandler):
        server_version = "vitals"

        def log_message(self, fmt, *args):
            log.debug("%s %s", self.address_string(), fmt % args)

        def _send(self, code: int, body: bytes, ctype: str, headers: dict | None = None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _token_ok(self, token: str | None) -> bool:
            return bool(token) and any(isinstance(t, str) and t and hmac.compare_digest(t.encode(), token.encode())
                                       for t in mon.cfg.tokens.values())

        def _authed(self) -> bool:
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer ") and self._token_ok(auth[7:].strip()):
                return True
            for part in self.headers.get("Cookie", "").split(";"):
                k, _, v = part.strip().partition("=")
                if (k == COOKIE or k in OLD_COOKIES) and self._token_ok(v):
                    return True
            return False

        def _agent_token_ok(self, token: str | None) -> bool:
            want = mon.cfg.agents.get("token")
            return bool(token) and isinstance(want, str) and bool(want) and hmac.compare_digest(want.encode(), token.encode())

        def _server_url(self) -> str:
            """The address agents should use: [agents] server_url, else the one this request came in on."""
            if mon.cfg.agents.get("server_url"):
                return str(mon.cfg.agents["server_url"]).rstrip("/")
            proto = "https" if self.headers.get("X-Forwarded-Proto", "").lower() == "https" else "http"
            host = (self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or "").split(",")[0].strip()
            if not re.fullmatch(r"[A-Za-z0-9.\-]+(:\d{1,5})?|\[[0-9A-Fa-f:.]+\](:\d{1,5})?", host):
                host = f"localhost:{mon.cfg.port}"   # it goes into a script: nothing odd gets through
            return f"{proto}://{host}"

        def _json(self, obj, code: int = 200):
            self._send(code, json.dumps(obj, separators=(",", ":")).encode(), "application/json")

        def _read_json(self, limit: int):
            n = int(self.headers.get("Content-Length") or 0)
            if n > limit:
                raise ValueError("too large")
            return json.loads(self.rfile.read(n).decode("utf-8-sig") or "null")

        def _same_origin(self) -> bool:
            """Settings changes come from our own page: JSON (no cross-site form can send
            that without a preflight) and, when the browser says where from, from here."""
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                return False
            origin = self.headers.get("Origin")
            return not origin or urlparse(origin).netloc == self.headers.get("Host", "")

        def _settings_write(self, method: str):
            if not self._authed():
                return self._json({"error": "token required"}, 401)
            if not self._same_origin():
                return self._json({"error": "send JSON from the settings page"}, 403)
            try:
                body = self._read_json(MAX_SETTINGS)
            except ValueError:
                return self._json({"error": "not JSON, or too large"}, 400)
            path = urlparse(self.path).path
            if method == "PUT" and path == "/api/settings":
                try:
                    doc = settings.clean(body, settings.load_doc())
                    settings.save_doc(doc)
                except settings.Invalid as e:
                    return self._json({"error": str(e)}, 422)
                except OSError as e:
                    return self._json({"error": str(e)}, 500)
                mon.apply_config(config.load())
                return self._json(settings_view(mon))
            if method == "POST" and path == "/api/settings/test":
                n = next((n for n in mon.cfg.notifiers if n["name"] == (body or {}).get("notifier")), None)
                if not n:
                    return self._json({"error": "save the notifier first, then test it"}, 404)
                try:
                    notify.SENDERS[n["type"]](n, {"kind": "test", "at": 0}, mon.cfg.title)
                except Exception as e:
                    return self._json({"ok": False, "error": str(e)[:300]})
                return self._json({"ok": True})
            return self._json({"error": "not found"}, 404)

        def do_PUT(self):
            self._settings_write("PUT")

        def do_POST(self):
            if urlparse(self.path).path.startswith("/api/settings"):
                return self._settings_write("POST")
            if urlparse(self.path).path != "/api/report":
                return self._send(404, b"not found", "text/plain")
            auth = self.headers.get("Authorization", "")
            if not self._agent_token_ok(auth[7:].strip() if auth.startswith("Bearer ") else None):
                return self._send(401, b'{"error":"agent token required"}', "application/json")
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_REPORT:
                return self._send(413, b'{"error":"report too large"}', "application/json")
            try:
                doc = json.loads(self.rfile.read(n).decode("utf-8-sig"))
            except ValueError:
                return self._send(400, b'{"error":"not JSON"}', "application/json")
            name = mon.agent_report(doc, ip=self.client_address[0]) if isinstance(doc, dict) else None
            if not name:
                return self._send(400, b'{"error":"report needs a name (letters, digits, - _ .)"}', "application/json")
            # The agent compares agent_version with its own and updates itself if they differ.
            self._send(200, json.dumps({"ok": True, "name": name, "agent_version": agents.AGENT_VERSION}).encode(),
                       "application/json")

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            u = urlparse(self.path)
            if u.path == "/healthz":
                return self._send(200, b"ok", "text/plain")
            token = parse_qs(u.query).get("token", [None])[0]
            if u.path in AGENT_FILES:
                if not self._agent_token_ok(token) or not re.fullmatch(r"[A-Za-z0-9._~+/=-]+", token):
                    return self._send(401, b"agent token required: ?token=<[agents] token>\n", "text/plain")
                f, ctype = AGENT_FILES[u.path]
                body = f.read_text(encoding="utf-8")
                if u.path.startswith("/install"):
                    body = body.replace("__SERVER__", self._server_url()).replace("__TOKEN__", token)
                return self._send(200, body.encode("utf-8"), f"{ctype}; charset=utf-8")
            if token and self._token_ok(token):
                # Swap the token in the address bar for a cookie, so it doesn't sit in history.
                return self._send(302, b"", "text/plain", {
                    "Location": "settings" if u.path == "/settings" else "./",
                    "Set-Cookie": f"{COOKIE}={token}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax"})
            full = self._authed()
            if u.path in ("/api/settings", "/api/activity") and not full:
                return self._json({"error": "token required"}, 401)
            if u.path == "/settings" and not full:
                return self._send(401, b"Settings need a token: open /settings?token=...\n", "text/plain; charset=utf-8")
            if u.path == "/settings":
                return self._send(200, (WEB / "settings.html").read_bytes(), "text/html; charset=utf-8", PAGE_CSP)
            if u.path == "/api/settings":
                return self._json(settings_view(mon))
            if u.path == "/api/activity":
                return self._json(list(reversed(mon.activity)))
            if not full and not mon.cfg.public_status:
                if u.path == "/api/status":
                    return self._send(401, b'{"error":"token required"}', "application/json")
                return self._send(401, b"This status page needs a token: open it as /?token=...\n",
                                  "text/plain; charset=utf-8")
            if u.path == "/api/status":
                return self._send(200, json.dumps(mon.status(full), separators=(",", ":")).encode(), "application/json")
            if u.path in ("/", "/index.html"):
                return self._send(200, (WEB / "index.html").read_bytes(), "text/html; charset=utf-8", PAGE_CSP)
            self._send(404, b"not found", "text/plain")

    return Handler


def settings_view(mon: Monitor) -> dict:
    """Everything the settings page shows and edits. Secrets are masked."""
    doc = settings.load_doc()
    doc["notifiers"] = [settings.notifier_view(n) for n in doc.get("notifiers") or []]
    cfg = mon.cfg
    st = mon.status(True)
    by_id = {r["id"]: r for r in st["checks"]}
    checks_out = [{"id": c.id, "name": c.name, "group": c.group or ("Hosts" if c.source == "agent" else ""),
                   "source": c.source, "type": c.type, "status": (by_id.get(c.id) or {}).get("status", "pending"),
                   "from_page": c.source == "config" and c.name in {d["name"] for d in doc.get("checks") or []}}
                  for c in mon.all_checks()]
    return {
        "doc": doc,
        "notifiers": [settings.notifier_view(n) for n in cfg.notifiers],
        "events": [{"id": e, "label": settings.EVENT_LABELS[e]} for e in settings.EVENTS],
        "fields": list(settings.FIELDS),
        "site_format": notify.SITE_FORMAT,
        "checks": checks_out,
        "hosts": [{"name": h, "ip": v.get("ip"), "last": v.get("last"), "summary": v.get("summary"),
                   "os": (v.get("report") or {}).get("os")} for h, v in sorted(mon.hosts.items())],
        "agents": {k: v for k, v in agents.host_conf(cfg.agents, "").items() if k in settings.AGENT_KEYS},
        "agent_hosts": cfg.agents.get("hosts") or {},
        "agents_token": bool(cfg.agents.get("token")),
        "agent_token": cfg.agents.get("token") or "",   # the page is token-protected; it shows the install lines
        "sites": [{**s, "status": (by_id.get(f"site:{s['name']}") or {}).get("status", "pending"),
                   "detail": (by_id.get(f"site:{s['name']}") or {}).get("detail", ""),
                   "from_page": s["name"] in {x["name"] for x in doc.get("sites") or []}} for s in cfg.sites],
        "quiet": cfg.quiet, "remind_every": cfg.remind_every,
        "can_save": settings.path() is not None, "title": cfg.title, "errors": cfg.errors,
    }


def lan_ip() -> str:
    """This machine's LAN address (a UDP connect sends nothing), for the first-run hint.
    Inside a container that would be the container's own address, so say so instead."""
    import os
    import socket
    if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
        return "<your-docker-host>"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            return s.getsockname()[0]
    except OSError:
        return "<this-machine>"


def serve(mon: Monitor, port: int) -> None:
    httpd = ThreadingHTTPServer(("0.0.0.0", port), make_handler(mon))
    httpd.daemon_threads = True
    mon.start()   # only once the page is listening, so a check of Vitals itself passes from the start
    log.info("status page on :%d%s", port, " (public)" if mon.cfg.public_status else "")
    if mon.cfg.made_tokens.get("page"):
        log.info("first time? open http://%s:%d/settings?token=%s (the token is kept in the data folder)",
                 lan_ip(), port, mon.cfg.made_tokens["page"])
    httpd.serve_forever()
