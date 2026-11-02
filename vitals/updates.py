"""Is there a newer Vitals than this one? The image knows the commit it was built
from (VITALS_BUILD); every 6 hours this asks GitHub for the newest commit on main.
Turn it off with [updates] check = false; point it elsewhere with repo = "owner/name".
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.request

log = logging.getLogger(__name__)
EVERY = 6 * 3600
latest: dict = {}   # {"sha", "message", "date", "checked"} once known


def build() -> str:
    return os.environ.get("VITALS_BUILD", "")


def check(repo: str) -> None:
    req = urllib.request.Request(f"https://api.github.com/repos/{repo}/commits/main",
                                 headers={"Accept": "application/vnd.github+json", "User-Agent": "vitals"})
    with urllib.request.urlopen(req, timeout=15) as r:
        c = json.loads(r.read())
    latest.update(sha=c["sha"], message=c["commit"]["message"].splitlines()[0][:120],
                  date=c["commit"]["committer"]["date"], checked=time.time())


def start(cfg) -> None:
    conf = getattr(cfg, "updates", {}) or {}
    if conf.get("check") is False or not build():
        return   # turned off, or not a published image (no build commit to compare)

    def loop():
        while True:
            try:
                check(conf.get("repo", "kylechrisking/vitals"))
            except Exception as e:
                log.info("update check: %s", e)
            time.sleep(EVERY)
    threading.Thread(target=loop, daemon=True, name="updates").start()


def status() -> dict | None:
    """What the settings page shows: None when up to date or unknown."""
    if not latest.get("sha") or not build() or latest["sha"].startswith(build()[:12]) or build().startswith(latest["sha"]):
        return None
    return {"running": build()[:7], "latest": latest["sha"][:7], "message": latest["message"], "date": latest["date"]}
