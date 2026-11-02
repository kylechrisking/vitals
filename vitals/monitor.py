"""The monitor: runs checks on schedule, decides up/down, keeps uptime and
incidents, and hands alerts to the notifiers.

A check is "down" only after `fail_after` failures in a row, and "up" again
on the first success. Alerts go out on those two transitions (plus optional
reminders), never on every failed run. During a maintenance window checks
still run but nothing alerts and the outage does not count against uptime.
During quiet hours alerts are held and sent as one digest when they end,
unless a notifier opts out of quiet hours.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from . import agents, checks, notify
from .config import Check, Config, data_dir
from .sett import SettFeed
from urllib.parse import urlparse

log = logging.getLogger(__name__)

BUCKET = 3600              # uptime is kept per hour...
KEEP_BUCKETS = 24 * 90     # ...for 90 days
KEEP_INCIDENTS = 500
KEEP_ACTIVITY = 500
SITE_EVERY = 15            # seconds between site evaluations
SAVE_EVERY = 60


@dataclass
class State:
    status: str = "pending"          # pending | up | down
    fails: int = 0
    oks: int = 0                     # successes in a row (for recover_after)
    last_ping: float = 0             # push checks: the last check-in
    since: float = 0                 # when the current status began
    last_run: float = 0
    detail: str = ""
    latency_ms: int | None = None
    alerted: bool = False            # a "down" alert went out for the current outage
    last_reminder: float = 0
    incident: int | None = None      # index into incidents while down
    buckets: dict[int, list[int]] = field(default_factory=dict)   # hour -> [ok, total]

    def to_json(self) -> dict:
        d = {k: getattr(self, k) for k in ("status", "since", "detail", "alerted", "last_reminder", "last_ping")}
        d["buckets"] = {str(k): v for k, v in self.buckets.items()}
        return d


class Monitor:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.states: dict[str, State] = {}
        self.incidents: list[dict] = []
        self.held: list[dict] = []       # alerts held back by quiet hours
        self.hosts: dict[str, dict] = {}  # agent name -> {"last": time, "report": doc, "summary": str, "ip": str}
        self.activity: deque = deque(maxlen=KEEP_ACTIVITY)   # every alert, sent or not, newest last
        self.disk_history: dict[str, dict[str, list]] = {}
        self.last_weekly = 0.0                           # when the last weekly summary was due  # host -> disk -> [[time, used %], ...] hourly
        self.lock = threading.RLock()
        self.pool = ThreadPoolExecutor(max_workers=32, thread_name_prefix="check")
        self.running: set[str] = set()
        self.sett = SettFeed(cfg.sett) if cfg.sett.get("url") else None
        self.data = data_dir()
        self.state_file = self.data / "state.json" if self.data else None
        self.started = time.time()
        self.load()

    # ---- the checks in play -----------------------------------------------------

    def all_checks(self) -> list[Check]:
        out = list(self.cfg.checks)
        if self.sett:
            out += self.sett.checks()
        for name, h in list(self.hosts.items()):
            out += [c for c, _ in agents.evaluate(name, h["report"], agents.host_conf(self.cfg.agents, name))]
        out += [site_check(s) for s in self.cfg.sites]
        return out

    # ---- sites ---------------------------------------------------------------------------

    def _members(self, site: dict, by_id: dict[str, Check]) -> list[Check]:
        """A site's members: check ids, or names (case-insensitive) for hand-written configs."""
        by_name = {c.name.lower(): c for c in by_id.values()}
        out = []
        for m in site.get("members") or []:
            c = by_id.get(m) or by_name.get(str(m).lower())
            if c and c.source != "site":
                out.append(c)
        return out

    def _sites(self, now: float) -> None:
        """A site is down when at least `count` of its members are down at the same time
        (all of them, if count isn't set). One machine rebooting is not a site outage."""
        if not self.cfg.sites:
            return
        by_id = self.by_id()
        for site in self.cfg.sites:
            c = site_check(site)
            st = self.states.setdefault(c.id, State(since=now))
            if now - st.last_run < SITE_EVERY:
                continue
            st.last_run = now
            members = self._members(site, by_id)
            if not members:
                continue
            down = [m for m in members if (self.states.get(m.id) or State()).status == "down"
                    and not self.in_maintenance(m, now)]
            need = min(int(site.get("count") or len(members)), len(members))
            detail = (f"{len(down)} of {len(members)} down: {', '.join(m.name for m in down)}" if down
                      else f"all {len(members)} up")
            self.record(c, checks.Result(len(down) < need, detail), now)

    # ---- host agents -------------------------------------------------------------------

    def agent_report(self, doc: dict, now: float | None = None, ip: str | None = None) -> str | None:
        """Take one agent report: remember the host and record each of its checks."""
        now = now or time.time()
        name = agents.clean_name(doc.get("name"))
        if not name:
            return None
        conf = agents.host_conf(self.cfg.agents, name)
        doc = agents.normalize(doc)
        doc["forecast"] = self._disk_trend(name, doc, now)
        with self.lock:
            new = name not in self.hosts
            self.hosts[name] = {"last": now, "report": doc, "summary": agents.summary(doc),
                                "ip": ip or (self.hosts.get(name) or {}).get("ip")}
        if new:
            log.info("agent: %s reporting (%s, agent %s)", name, doc.get("os"), doc.get("agent"))
        for c, r in agents.evaluate(name, doc, conf):
            self.states.setdefault(c.id, State(since=now)).last_run = now
            self.record(c, r, now)
        return name

    def _disk_trend(self, host: str, doc: dict, now: float) -> dict[str, float]:
        """Keep an hourly used-% sample per disk for 30 days; return days-until-full per disk."""
        hist = self.disk_history.setdefault(host, {})
        out = {}
        for d in doc.get("disks") or []:
            s = hist.setdefault(d["mount"], [])
            if not s or now - s[-1][0] >= 3600:
                s.append([now, round(float(d["used_pct"]), 2)])
                del s[:-720]
            days = agents.forecast(s + ([[now, float(d["used_pct"])]] if now - s[-1][0] > 0 else []), now)
            if days is not None:
                out[d["mount"]] = round(days, 1)
        for m in [m for m in hist if m not in {d["mount"] for d in doc.get("disks") or []}]:
            if hist[m] and now - hist[m][-1][0] > 30 * 86400:
                del hist[m]
        return out

    def _agent_heartbeats(self, now: float) -> None:
        for name, h in list(self.hosts.items()):
            conf = agents.host_conf(self.cfg.agents, name)
            if now - h["last"] > agents.FORGET_AFTER:
                self._forget_host(name)
                continue
            late = agents.missed(h["last"], conf, now)
            if late is None:
                continue
            c = agents.heartbeat(name, conf)
            st = self.states.setdefault(c.id, State(since=now))
            if now - st.last_run >= float(conf["every"]):
                st.last_run = now
                self.record(c, checks.Result(False, f"no report for {fmt_duration(late)}"), now)

    def _forget_host(self, name: str) -> None:
        with self.lock:
            self.hosts.pop(name, None)
            for cid in [k for k in self.states if k.startswith(f"agent:{name}/")]:
                st = self.states.pop(cid)
                if st.incident is not None:
                    self.incidents[st.incident].update(end=time.time(), note="host forgotten")
        log.info("agent: forgot %s (silent for 30 days)", name)

    def by_id(self) -> dict[str, Check]:
        return {c.id: c for c in self.all_checks()}

    # ---- loops -----------------------------------------------------------------------

    def start(self) -> None:
        threading.Thread(target=self._schedule_loop, daemon=True, name="schedule").start()
        threading.Thread(target=self._save_loop, daemon=True, name="save").start()
        threading.Thread(target=self._watch_loop, daemon=True, name="watch").start()
        if self.sett:
            threading.Thread(target=self._sett_loop, args=(self.sett,), daemon=True, name="sett").start()

    def _schedule_loop(self) -> None:
        while True:
            try:
                self.tick()
            except Exception:
                log.exception("scheduler")
            time.sleep(1)

    def tick(self, now: float | None = None) -> None:
        """Start every check that is due, send reminders, flush held alerts."""
        now = now or time.time()
        for c in self.cfg.checks:
            st = self.states.setdefault(c.id, State(since=now))
            if c.type == "push":
                self._push_due(c, st, now)
                continue
            with self.lock:
                if c.id in self.running or now - st.last_run < c.every:
                    continue
                self.running.add(c.id)
                st.last_run = now
            self.pool.submit(self._run, c)
        self._agent_heartbeats(now)
        self._sites(now)
        self._weekly(now)
        self._remind(now)
        self._flush_held(now)

    # ---- check-ins from scheduled jobs -----------------------------------------------------

    def push_token(self, c: Check) -> str:
        """The secret in a check-in URL: the check's own token, else one derived from the
        check's name and this install's secret (stable across restarts)."""
        if c.token:
            return c.token
        import base64
        import hashlib
        import hmac as _hmac
        mac = _hmac.new(self.cfg.push_secret.encode(), c.name.encode(), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(mac).decode()[:22]

    def push(self, token: str, ok: bool = True, msg: str = "", now: float | None = None) -> str | None:
        """A job checked in. Returns the check's name, or None for an unknown token."""
        import hmac as _hmac
        now = now or time.time()
        for c in self.cfg.checks:
            if c.type == "push" and _hmac.compare_digest(self.push_token(c), token):
                st = self.states.setdefault(c.id, State(since=now))
                st.last_ping = st.last_run = now
                self.record(c, checks.Result(ok, msg[:200] or ("checked in" if ok else "the job reported a failure")), now)
                return c.name
        return None

    @staticmethod
    def grace(c: Check) -> float:
        return c.grace or min(3600.0, max(300.0, c.every * 0.1))

    def _push_due(self, c: Check, st: State, now: float) -> None:
        """No check-in within every + grace: that's a failure, recorded at most every few minutes."""
        last = st.last_ping or self.started
        late = now - last
        if late > c.every + self.grace(c) and now - st.last_run >= min(c.every, 300):
            st.last_run = now
            word = "no check-in yet" if not st.last_ping else f"no check-in for {fmt_duration(late)}"
            self.record(c, checks.Result(False, word), now)

    def _run(self, c: Check) -> None:
        try:
            self.record(c, checks.run(c))
        finally:
            with self.lock:
                self.running.discard(c.id)

    def _sett_loop(self, feed: SettFeed) -> None:
        while feed is self.sett:
            results = feed.poll()
            now = time.time()
            for c, r in results:
                self.states.setdefault(c.id, State(since=now)).last_run = now
                self.record(c, r)
            self._forget_missing({c.id for c in feed.checks()})
            time.sleep(feed.every)

    def _forget_missing(self, live: set[str]) -> None:
        """A service Sett no longer reports (removed, renamed) stops being watched;
        an open outage for it is closed rather than left down forever."""
        with self.lock:
            for cid in [k for k in self.states if k.startswith("sett:") and k not in live]:
                st = self.states.pop(cid)
                if st.incident is not None:
                    self.incidents[st.incident].update(end=time.time(), note="no longer reported by Sett")

    def _save_loop(self) -> None:
        while True:
            time.sleep(SAVE_EVERY)
            self.save()

    def _watch_loop(self) -> None:
        from . import config
        while True:
            time.sleep(5)
            if not config.changed(self.cfg):
                continue
            try:
                new = config.load()
            except Exception as e:
                log.warning("config not reloaded: %s", e)
                self.cfg.files = {f: config._mtime(Path(f)) for f in self.cfg.files}
                continue
            self.apply_config(new)

    def apply_config(self, new: Config) -> None:
        """Switch to a new config (file edited, or saved from the settings page)."""
        if True:
            new.port = self.cfg.port
            sett_changed = new.sett != self.cfg.sett
            self.cfg = new
            if sett_changed:
                self.sett = SettFeed(new.sett) if new.sett.get("url") else None
                if self.sett:
                    threading.Thread(target=self._sett_loop, args=(self.sett,), daemon=True, name="sett").start()
                else:
                    self._forget_missing(set())
            live = {c.id for c in new.checks}
            with self.lock:
                for cid in [k for k in self.states if k.startswith("config:") and k not in live]:
                    del self.states[cid]
            log.info("config reloaded: %d checks, %d notifiers", len(new.checks), len(new.notifiers))

    # ---- deciding --------------------------------------------------------------------

    def record(self, c: Check, r: checks.Result, now: float | None = None) -> None:
        now = now or time.time()
        maint = self.in_maintenance(c, now)
        event = None
        with self.lock:
            st = self.states.setdefault(c.id, State(since=now))
            st.detail, st.latency_ms = r.detail, r.latency_ms
            hour = int(now // BUCKET)
            if not maint:   # maintenance does not count against uptime
                b = st.buckets.setdefault(hour, [0, 0])
                b[0] += r.ok
                b[1] += 1
                for old in [h for h in st.buckets if h < hour - KEEP_BUCKETS]:
                    del st.buckets[old]
            if r.ok:
                st.fails = 0
                st.oks += 1
                if st.status == "down" and st.oks < c.recover_after:
                    pass   # one good reading isn't a recovery yet
                elif st.status != "up":
                    was_down = st.status == "down"
                    if was_down and st.incident is not None:
                        self.incidents[st.incident]["end"] = now
                    if was_down and st.alerted and not maint:
                        event = self._event("up", c, st, now)
                    st.status, st.since, st.alerted, st.incident = "up", now, False, None
            else:
                st.oks = 0
                st.fails += 1
                if st.fails >= c.fail_after and st.status != "down":
                    st.status, st.since = "down", now
                    self.incidents.append({"check": c.name, "id": c.id, "group": c.group, "start": now,
                                           "end": None, "detail": r.detail, "public": c.public,
                                           "maintenance": maint, "about": about(c)})
                    if len(self.incidents) > KEEP_INCIDENTS:
                        drop = len(self.incidents) - KEEP_INCIDENTS
                        self.incidents = self.incidents[drop:]
                        for s in self.states.values():
                            if s.incident is not None:
                                s.incident = s.incident - drop if s.incident >= drop else None
                    st.incident = len(self.incidents) - 1
                    if not maint:
                        st.alerted = True
                        st.last_reminder = now
                        event = self._event("down", c, st, now)
        if event:
            self.dispatch(event, c, now)

    def _event(self, kind: str, c: Check, st: State, now: float) -> dict:
        ev = {"kind": kind, "check": c.name, "id": c.id, "group": c.group, "type": c.type, "target": c.target,
              "address": self.address(c), "detail": st.detail, "at": now, "about": about(c)}
        if kind in ("up", "reminder"):
            ev["down_for"] = now - (self.incidents[st.incident]["start"] if st.incident is not None else st.since)
        return ev

    def acknowledge(self, check_id: str, who: str = "", now: float | None = None) -> bool:
        """Someone knows about this outage: no more reminders for it. Ends with the outage."""
        with self.lock:
            st = self.states.get(check_id)
            if not st or st.status != "down" or st.incident is None:
                return False
            self.incidents[st.incident]["acked"] = {"at": now or time.time(), "by": who[:40]}
        return True

    def _remind(self, now: float) -> None:
        every = self.cfg.remind_every * 60
        if not every:
            return
        checks_by_id = self.by_id()
        for cid, st in list(self.states.items()):
            c = checks_by_id.get(cid)
            acked = st.incident is not None and self.incidents[st.incident].get("acked")
            if c and st.status == "down" and st.alerted and not acked and now - st.last_reminder >= every:
                st.last_reminder = now
                self.dispatch(self._event("reminder", c, st, now), c, now)

    # ---- maintenance and quiet hours -------------------------------------------------------

    def in_maintenance(self, c: Check, now: float) -> bool:
        """One-off windows (start/end) and repeating ones (days + from/to, local time)."""
        for w in self.cfg.maintenance:
            names = w.get("checks") or []
            if names and not (c.name in names or c.group in names or c.id in names):
                continue
            if "from" in w:
                if _in_daily_window(now, w.get("days") or [], w["from"], w["to"]):
                    return True
                continue
            try:
                if _when(w["start"]) <= now < _when(w["end"]):
                    return True
            except (KeyError, ValueError):
                continue
        return False

    def quiet(self, now: float) -> bool:
        span = self.cfg.quiet.get("hours")
        if not span:
            return False
        try:
            a, b = (datetime.strptime(x.strip(), "%H:%M").time() for x in span.split("-"))
        except ValueError:
            return False
        t = datetime.fromtimestamp(now).time()
        return a <= t < b if a < b else t >= a or t < b

    def dispatch(self, ev: dict, c: Check, now: float) -> None:
        """Send an alert to every notifier that wants it, and log it either way."""
        muted = c.id in self.cfg.muted
        targets = [] if muted else [n for n in self.cfg.notifiers
                                    if (not c.notify or n["name"] in c.notify) and wants(n, ev)]
        held: list[str] = []
        if targets and self.quiet(now):
            held = [n["name"] for n in targets if not n.get("ignore_quiet")]
            if held:
                with self.lock:
                    self.held.append({**ev, "notifiers": held})
            targets = [n for n in targets if n.get("ignore_quiet")]
        with self.lock:
            self.activity.append({k: ev.get(k) for k in ("kind", "about", "check", "id", "address", "detail", "at",
                                                        "down_for")}
                                 | {"sent": [n["name"] for n in targets], "held": held, "muted": muted})
        for n in targets:
            self.pool.submit(notify.send, n, ev, self.cfg.title)

    # ---- the weekly summary -----------------------------------------------------------------

    def _weekly(self, now: float) -> None:
        """Monday 09:00 local time: the week in review, to notifiers that take "weekly".
        A summary missed by more than 12 hours (Vitals was down) is skipped, not sent late."""
        due = last_monday_9(now)
        if due <= self.last_weekly:
            return
        first = not self.last_weekly
        self.last_weekly = due
        if first or now - due > 12 * 3600:
            return
        ev = self.weekly_summary(now)
        targets = [n for n in self.cfg.notifiers if wants(n, ev)]
        with self.lock:
            self.activity.append({"kind": "weekly", "about": "weekly", "check": "Weekly summary", "at": now,
                                  "detail": ev["headline"], "sent": [n["name"] for n in targets], "held": [], "muted": False})
        for n in targets:
            self.pool.submit(notify.send, n, ev, self.cfg.title)

    def weekly_summary(self, now: float) -> dict:
        week = now - 7 * 86400
        by_id = self.by_id()
        lines = []
        sites = [c for c in by_id.values() if c.source == "site"]
        if sites:
            lines.append("Sites: " + ", ".join(f"{c.name} {_pct(self.uptime(self.states.get(c.id) or State(), 168, now))}"
                                              for c in sites))
        outages: dict[str, list[float]] = {}
        for i in self.incidents:
            if (i.get("end") or now) >= week and not i.get("maintenance"):
                outages.setdefault(i["check"], []).append(min(i.get("end") or now, now) - max(i["start"], week))
        if outages:
            worst = sorted(outages.items(), key=lambda kv: -sum(kv[1]))[:8]
            lines.append("Down this week: " + "; ".join(
                f"{name} {len(d)}x, {fmt_duration(sum(d))}" for name, d in worst))
        else:
            lines.append("Nothing went down this week.")
        if self.hosts:
            problems = [c.name for c in by_id.values() if c.source == "agent" and not c.key.endswith("/host")
                        and (self.states.get(c.id) or State()).status == "down"]
            lines.append(f"Hosts: {len(self.hosts)} reporting" + (f"; problems now: {', '.join(problems)}" if problems else ", no problems"))
            filling = [f"{h} {m} full in ~{d:.0f}d" for h, v in self.hosts.items()
                       for m, d in ((v.get("report") or {}).get("forecast") or {}).items() if d < 30]
            if filling:
                lines.append("Filling up: " + ", ".join(filling))
        headline = f"{len(outages)} {'thing' if len(outages) == 1 else 'things'} went down" if outages else "a quiet week"
        return {"kind": "weekly", "about": "weekly", "at": now, "lines": lines, "headline": headline}

    def address(self, c: Check) -> str:
        """Where a check points, for messages: a host's IP, a URL's host, a host:port's host."""
        if c.source == "agent":
            return (self.hosts.get(c.target) or {}).get("ip") or c.target
        if c.source == "site":
            if c.target:
                return c.target
            members = self._members(next((s for s in self.cfg.sites if s["name"] == c.name), {}), self.by_id())
            return next((a for a in (self.address(m) for m in members) if a), "")
        t = c.target
        if "://" in t:
            return urlparse(t).hostname or t
        return t.rsplit(":", 1)[0] if t.count(":") == 1 else t

    def _flush_held(self, now: float) -> None:
        if not self.held or self.quiet(now):
            return
        with self.lock:
            held, self.held = self.held, []
        by_notifier: dict[str, list[dict]] = {}
        for ev in held:
            for name in ev["notifiers"]:
                by_notifier.setdefault(name, []).append(ev)
        current = {cid: st.status for cid, st in self.states.items()}
        names = {c.name: c.id for c in self.all_checks()}
        for n in self.cfg.notifiers:
            evs = by_notifier.get(n["name"])
            if evs:
                digest = {"kind": "digest", "at": now, "events": evs,
                          "still_down": sorted({e["check"] for e in evs if current.get(names.get(e["check"])) == "down"})}
                self.pool.submit(notify.send, n, digest, self.cfg.title)

    # ---- reporting -------------------------------------------------------------------------

    def uptime(self, st: State, hours: int, now: float | None = None) -> float | None:
        h = int((now or time.time()) // BUCKET)
        ok = total = 0
        for hour, (o, t) in st.buckets.items():
            if hour > h - hours:
                ok, total = ok + o, total + t
        return round(100 * ok / total, 3) if total else None

    def status(self, full: bool, now: float | None = None) -> dict:
        """Everything the page and /api/status show. `full` adds targets and
        error details and the non-public checks; the public page gets neither."""
        now = now or time.time()
        rows = []
        for c in self.all_checks():
            if not full and not c.public:
                continue
            st = self.states.get(c.id) or State(since=now)
            inc = self.incidents[st.incident] if st.incident is not None and st.incident < len(self.incidents) else {}
            row = {"id": c.id, "name": c.name, "group": c.group or ("Sett" if c.source == "sett" else ""),
                   "acked": bool(inc.get("acked")),
                   "last_ping": st.last_ping or None if c.type == "push" else None,
                   "type": c.type, "status": "maintenance" if self.in_maintenance(c, now) else st.status,
                   "since": st.since, "latency_ms": st.latency_ms, "source": c.source,
                   "uptime": {"24h": self.uptime(st, 24, now), "7d": self.uptime(st, 24 * 7, now),
                              "30d": self.uptime(st, 24 * 30, now), "90d": self.uptime(st, 24 * 90, now)},
                   "bars": self.bars(st, now)}
            if full:
                row.update(target=c.target, detail=st.detail, every=c.every)
                if c.source == "agent" and c.key.endswith("/host") and c.target in self.hosts:
                    row["summary"] = self.hosts[c.target]["summary"]
            rows.append(row)
        incidents = [i for i in reversed(self.incidents) if full or i.get("public", True)][:50]
        if not full:
            incidents = [{k: v for k, v in i.items() if k not in ("detail", "id")} for i in incidents]
        return {"title": self.cfg.title, "generated_at": now, "started": self.started,
                "checks": rows, "incidents": incidents,
                "summary": {"up": sum(r["status"] == "up" for r in rows), "down": sum(r["status"] == "down" for r in rows),
                            "total": len(rows)},
                "sett": (self.sett.state() if self.sett else None) if full else None,
                "errors": self.cfg.errors if full else [], "full": full,
                "update": __import__("vitals.updates", fromlist=["status"]).status() if full else None,
                "quiet": self.quiet(now), "held": len(self.held) if full else None}

    def bars(self, st: State, now: float, days: int = 30) -> list[float | None]:
        """Daily uptime for the last `days` days, oldest first (None: no data)."""
        today = int(now // 86400)
        per_day: dict[int, list[int]] = {}
        for hour, (o, t) in st.buckets.items():
            d = hour * BUCKET // 86400
            if d > today - days:
                acc = per_day.setdefault(d, [0, 0])
                acc[0] += o
                acc[1] += t
        return [round(100 * per_day[d][0] / per_day[d][1], 2) if d in per_day and per_day[d][1] else None
                for d in range(today - days + 1, today + 1)]

    # ---- persistence -------------------------------------------------------------------------

    def save(self) -> None:
        if not self.state_file:
            return
        with self.lock:
            doc = {"v": 1, "saved": time.time(), "incidents": self.incidents, "hosts": self.hosts,
                   "activity": list(self.activity), "disk_history": self.disk_history, "last_weekly": self.last_weekly,
                   "states": {k: s.to_json() for k, s in self.states.items()}}
        tmp = f"{self.state_file}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(doc, f, separators=(",", ":"))
            os.replace(tmp, self.state_file)
        except OSError as e:
            log.warning("could not save state: %s", e)

    def load(self) -> None:
        if not self.state_file or not self.state_file.is_file():
            return
        try:
            doc = json.loads(self.state_file.read_text(encoding="utf-8"))
            self.incidents = list(doc.get("incidents", []))[-KEEP_INCIDENTS:]
            self.hosts = {k: v for k, v in (doc.get("hosts") or {}).items()
                          if isinstance(v, dict) and "last" in v and isinstance(v.get("report"), dict)}
            self.activity.extend(a for a in doc.get("activity") or [] if isinstance(a, dict))
            self.last_weekly = float(doc.get("last_weekly") or 0)
            self.disk_history = {h: {m: [list(x) for x in s] for m, s in v.items()}
                                 for h, v in (doc.get("disk_history") or {}).items() if isinstance(v, dict)}
            open_by_id = {i["id"]: n for n, i in enumerate(self.incidents) if i.get("end") is None and "id" in i}
            for cid, d in doc.get("states", {}).items():
                st = State(status=d.get("status", "pending"), since=float(d.get("since", 0)),
                           detail=d.get("detail", ""), alerted=bool(d.get("alerted")),
                           last_reminder=float(d.get("last_reminder", 0)), last_ping=float(d.get("last_ping", 0)),
                           buckets={int(k): list(v) for k, v in d.get("buckets", {}).items()})
                if st.status == "down":
                    # Still down across a restart: keep the outage open and don't alert again.
                    st.incident = open_by_id.get(cid)
                    st.fails = 10 ** 6
                self.states[cid] = st
            log.info("state: %d checks, %d incidents restored", len(self.states), len(self.incidents))
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as e:
            log.warning("could not read %s: %s", self.state_file, e)


def site_check(site: dict) -> Check:
    return Check(name=site["name"], type="site", target=site.get("address") or "", every=SITE_EVERY,
                 fail_after=2, group="Sites", source="site", key=site["name"], public=bool(site.get("public", True)))


def wants(n: dict, ev: dict) -> bool:
    """Does notifier n take this alert? Its `events` (default: all of them) name
    the kinds it takes; `only` limits it to some checks, hosts, sites or groups."""
    from .settings import EVENTS
    if not n.get("enabled", True):
        return False
    if ev["kind"] == "test":
        return True
    events = n.get("events")
    events = EVENTS if events is None else events
    if ev["kind"] in ("digest", "weekly"):
        return ev["kind"] in events
    if ev.get("about", "service") not in events or (ev["kind"] == "reminder" and "reminder" not in events):
        return False
    only = n.get("only") or []
    host = str(ev.get("id", "")).split(":", 1)[-1].split("/", 1)[0] if ev.get("id", "").startswith("agent:") else None
    return not only or any(x in only for x in (ev.get("id"), ev.get("check"), ev.get("group"), host) if x)


def about(c: Check) -> str:
    """How to word an alert: "service" (is down / back up), "host" (stopped
    reporting), or "problem" (a disk, a certificate, a failing drive: something wrong, not something gone)."""
    if c.source == "site":
        return "site"
    if c.source == "agent":
        return "host" if c.key.endswith("/host") else "problem"
    if c.type == "tls" or c.key.startswith("node:"):
        return "problem"
    return "service"


_DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def last_monday_9(now: float) -> float:
    """The most recent Monday 09:00 (local time) at or before `now`."""
    t = datetime.fromtimestamp(now)
    monday = (t - timedelta(days=t.weekday())).replace(hour=9, minute=0, second=0, microsecond=0)
    if monday > t:
        monday -= timedelta(days=7)
    return monday.timestamp()


def _pct(v: float | None) -> str:
    return "–" if v is None else ("100%" if v >= 99.995 else f"{v:.2f}%")


def _in_daily_window(now: float, days: list[str], start: str, end: str) -> bool:
    """Is `now` inside from-to on one of `days` (all days if empty)? A window like
    23:30-01:00 belongs to the day it starts on."""
    try:
        a = datetime.strptime(start, "%H:%M").time()
        b = datetime.strptime(end, "%H:%M").time()
    except ValueError:
        return False
    t = datetime.fromtimestamp(now)
    today, yesterday = _DAYS[t.weekday()], _DAYS[(t.weekday() - 1) % 7]
    on = lambda d: not days or d in days   # noqa: E731
    if a < b:
        return on(today) and a <= t.time() < b
    return (on(today) and t.time() >= a) or (on(yesterday) and t.time() < b)


def _when(v) -> float:
    """A TOML datetime or an ISO string, local time unless it says otherwise."""
    if isinstance(v, datetime):
        return v.timestamp()
    if isinstance(v, (int, float)):
        return float(v)
    return datetime.fromisoformat(str(v)).timestamp()


def fmt_duration(seconds: float) -> str:
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h {s % 3600 // 60}m"
    return str(timedelta(seconds=s)).split(",")[0] + f" {s % 86400 // 3600}h"
