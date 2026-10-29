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

from .monitor import Monitor

log = logging.getLogger(__name__)
WEB = Path(__file__).parent / "web"
HERE = Path(__file__).parent
# Agent files, served to machines that present the agent token.
AGENT_FILES = {"/agent.py": (HERE / "agent.py", "text/x-python"), "/agent.ps1": (HERE / "agent.ps1", "text/plain"),
               "/install.sh": (HERE / "install" / "install.sh", "text/x-shellscript"),
               "/install.ps1": (HERE / "install" / "install.ps1", "text/plain")}
MAX_REPORT = 256 * 1024
COOKIE = "brock_token"


def make_handler(mon: Monitor):
    class Handler(BaseHTTPRequestHandler):
        server_version = "brock"

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
                if k == COOKIE and self._token_ok(v):
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

        def do_POST(self):
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
            self._send(200, json.dumps({"ok": True, "name": name}).encode(), "application/json")

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
                    "Location": "./", "Set-Cookie": f"{COOKIE}={token}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax"})
            full = self._authed()
            if not full and not mon.cfg.public_status:
                if u.path == "/api/status":
                    return self._send(401, b'{"error":"token required"}', "application/json")
                return self._send(401, b"This status page needs a token: open it as /?token=...\n",
                                  "text/plain; charset=utf-8")
            if u.path == "/api/status":
                return self._send(200, json.dumps(mon.status(full), separators=(",", ":")).encode(), "application/json")
            if u.path in ("/", "/index.html"):
                return self._send(200, (WEB / "index.html").read_bytes(), "text/html; charset=utf-8",
                                  {"Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                                                              "script-src 'self' 'unsafe-inline'; img-src 'self' data:"})
            self._send(404, b"not found", "text/plain")

    return Handler


def serve(mon: Monitor, port: int) -> None:
    httpd = ThreadingHTTPServer(("0.0.0.0", port), make_handler(mon))
    httpd.daemon_threads = True
    mon.start()   # only once the page is listening, so a check of Brock itself passes from the start
    log.info("status page on :%d%s", port, " (public)" if mon.cfg.public_status else "")
    httpd.serve_forever()
