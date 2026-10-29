"""Watch what Sett discovered, without listing it again.

    [sett]
    url = "http://sett.lan:8099"
    token = "..."              # a Sett [auth] api_tokens value, if Sett has sign-in
    every = 30                 # seconds between reads of Sett's /api/status
    fail_after = 2             # reads in a row a service must be down before it alerts
    exclude = ["flaresolverr"] # app ids, service names or categories to leave out
    node_health = true         # alert on Proxmox health Sett marks bad (failing disks, pools...)

Sett already probes every service; Vitals reads the result. If Sett itself
can't be reached, that is one "Sett" check going down, and the services keep
their last state rather than all alerting at once.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request

from . import __version__
from .checks import Result, _insecure
from .config import Check

log = logging.getLogger(__name__)
MISSING_GRACE = 600


class SettFeed:
    def __init__(self, conf: dict):
        self.url = conf["url"].rstrip("/")
        self.token = conf.get("token", "")
        self.every = float(conf.get("every", 30))
        self.fail_after = max(1, int(conf.get("fail_after", 2)))
        self.exclude = {str(x).lower() for x in conf.get("exclude", [])}
        self.node_health = bool(conf.get("node_health", True))
        self.notify = list(conf.get("notify", []))
        self.public = bool(conf.get("public", True))
        self._checks: dict[str, Check] = {}
        self._seen: dict[str, float] = {}   # key -> last time Sett reported it with a status
        self.self_check = Check(name="Sett", type="http", target=f"{self.url}/api/status", every=self.every,
                                fail_after=self.fail_after, group="Sett", notify=self.notify, public=self.public,
                                source="sett", key="_sett")
        self.last_ok: float | None = None
        self.last_error = ""
        self.count = 0

    def checks(self) -> list[Check]:
        return [self.self_check, *self._checks.values()]

    def state(self) -> dict:
        return {"url": self.url, "last_ok": self.last_ok, "error": self.last_error, "services": self.count}

    def fetch(self) -> dict:
        req = urllib.request.Request(f"{self.url}/api/status", headers={
            "User-Agent": f"vitals/{__version__}", "Accept": "application/json",
            **({"Authorization": f"Bearer {self.token}"} if self.token else {})})
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_insecure))
        with opener.open(req, timeout=10) as r:
            return json.loads(r.read(4 * 1024 * 1024))

    def poll(self) -> list[tuple[Check, Result]]:
        """One read of Sett: (check, result) for Sett itself and each service it reports."""
        t0 = time.monotonic()
        try:
            doc = self.fetch()
        except urllib.error.HTTPError as e:
            hint = " (set [sett] token to one of Sett's api_tokens)" if e.code == 401 else ""
            return [self._down(f"HTTP {e.code}{hint}")]
        except (urllib.error.URLError, OSError, ValueError) as e:
            return [self._down(str(getattr(e, "reason", e))[:200])]
        self.last_ok, self.last_error = time.time(), ""
        out = [(self.self_check, Result(True, "reachable", int((time.monotonic() - t0) * 1000)))]
        live: dict[str, Check] = {}
        now = time.time()
        for s in doc.get("services", []):
            key = s.get("key") or s.get("name")
            if s.get("status") not in ("up", "down") or self._excluded(s):
                if key in self._checks and not self._excluded(s):
                    live[key] = self._checks[key]   # not checked yet (Sett just restarted): keep its state
                continue   # "unknown" is otherwise a plain link card: nothing to watch
            self._seen[key] = now
            name = s["name"] + (f" ({s['host']})" if s.get("host") and s["host"].lower() not in s["name"].lower() else "")
            c = self._checks.get(key) or Check(name=name, type="sett", target=s.get("url") or key, every=self.every,
                                               fail_after=self.fail_after, group=s.get("category", ""),
                                               notify=self.notify, public=self.public, source="sett", key=key)
            c.name, c.group = name, s.get("category", "") or c.group
            c.target = s.get("url") or key
            live[key] = c
            out.append((c, Result(s["status"] == "up", s.get("error") or ("up" if s["status"] == "up" else "down"),
                                  s.get("latency_ms"))))
        if self.node_health:
            for n in doc.get("nodes", []):
                bad = [h for h in n.get("health", []) if h.get("tone") == "bad"]
                key = f"node:{n['name']}"
                c = self._checks.get(key) or Check(name=f"{n['name']} health", type="sett", target=key,
                                                   every=self.every, fail_after=1, group="Proxmox",
                                                   notify=self.notify, public=False, source="sett", key=key)
                live[key] = c
                detail = "; ".join(f"{h['label']}: {h['value']}" + (f" ({h['detail']})" if h.get("detail") else "")
                                   for h in bad)
                out.append((c, Result(not bad, detail or "healthy")))
        # A service missing from one read (Sett restarting, rediscovering) keeps its
        # state for a while instead of being forgotten and alerting afresh.
        for key, c in self._checks.items():
            if key not in live and now - self._seen.get(key, now) < MISSING_GRACE:
                live[key] = c
        for key in [k for k in self._seen if k not in live]:
            del self._seen[key]
        self._checks = live
        self.count = len(live)
        return out

    def _down(self, why: str) -> tuple[Check, Result]:
        self.last_error = why
        return self.self_check, Result(False, why)

    def _excluded(self, s: dict) -> bool:
        return any(str(s.get(k, "")).lower() in self.exclude for k in ("app", "name", "category", "key"))
