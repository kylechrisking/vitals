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
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from . import agents, checks, notify
from .config import Check, Config, data_dir
from .sett import SettFeed

log = logging.getLogger(__name__)

BUCKET = 3600              # uptime is kept per hour...
KEEP_BUCKETS = 24 * 90     # ...for 90 days
KEEP_INCIDENTS = 500
SAVE_EVERY = 60


@dataclass
class State:
    status: str = "pending"          # pending | up | down
    fails: int = 0
    since: float = 0                 # when the current status began
    last_run: float = 0
    detail: str = ""
    latency_ms: int | None = None
    alerted: bool = False            # a "down" alert went out for the current outage
    last_reminder: float = 0
    incident: int | None = None      # index into incidents while down
    buckets: dict[int, list[int]] = field(default_factory=dict)   # hour -> [ok, total]

    def to_json(self) -> dict:
        d = {k: getattr(self, k) for k in ("status", "since", "detail", "alerted", "last_reminder")}
        d["buckets"] = {str(k): v for k, v in self.buckets.items()}
        return d


class Monitor:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.states: dict[str, State] = {}
        self.incidents: list[dict] = []
        self.held: list[dict] = []       # alerts held back by quiet hours
        self.hosts: dict[str, dict] = {}  # agent name -> {"last": time, "report": doc, "summary": str}
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
        return out

    # ---- host agents -------------------------------------------------------------------

    def agent_report(self, doc: dict, now: float | None = None) -> str | None:
        """Take one agent report: remember the host and record each of its checks."""
        now = now or time.time()
        name = agents.clean_name(doc.get("name"))
        if not name:
            return None
        conf = agents.host_conf(self.cfg.agents, name)
        with self.lock:
            new = name not in self.hosts
            self.hosts[name] = {"last": now, "report": doc, "summary": agents.summary(doc)}
        if new:
            log.info("agent: %s reporting (%s, agent %s)", name, doc.get("os"), doc.get("agent"))
        for c, r in agents.evaluate(name, doc, conf):
            self.states.setdefault(c.id, State(since=now)).last_run = now
            self.record(c, r, now)
        return name

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
            with self.lock:
                if c.id in self.running or now - st.last_run < c.every:
                    continue
                self.running.add(c.id)
                st.last_run = now
            self.pool.submit(self._run, c)
        self._agent_heartbeats(now)
        self._remind(now)
        self._flush_held(now)

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
                if st.status != "up":
                    was_down = st.status == "down"
                    if was_down and st.incident is not None:
                        self.incidents[st.incident]["end"] = now
                    if was_down and st.alerted and not maint:
                        event = self._event("up", c, st, now)
                    st.status, st.since, st.alerted, st.incident = "up", now, False, None
            else:
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
        ev = {"kind": kind, "check": c.name, "group": c.group, "type": c.type, "target": c.target,
              "detail": st.detail, "at": now, "about": about(c)}
        if kind in ("up", "reminder"):
            ev["down_for"] = now - (self.incidents[st.incident]["start"] if st.incident is not None else st.since)
        return ev

    def _remind(self, now: float) -> None:
        every = self.cfg.remind_every * 60
        if not every:
            return
        checks_by_id = self.by_id()
        for cid, st in list(self.states.items()):
            c = checks_by_id.get(cid)
            if c and st.status == "down" and st.alerted and now - st.last_reminder >= every:
                st.last_reminder = now
                self.dispatch(self._event("reminder", c, st, now), c, now)

    # ---- maintenance and quiet hours -------------------------------------------------------

    def in_maintenance(self, c: Check, now: float) -> bool:
        for w in self.cfg.maintenance:
            try:
                start = _when(w["start"])
                end = _when(w["end"])
            except (KeyError, ValueError):
                continue
            names = w.get("checks") or []
            if start <= now < end and (not names or c.name in names or c.group in names):
                return True
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
        targets = [n for n in self.cfg.notifiers if not c.notify or n["name"] in c.notify]
        if self.quiet(now):
            loud = [n for n in targets if n.get("ignore_quiet")]
            held = [n["name"] for n in targets if not n.get("ignore_quiet")]
            if held:
                with self.lock:
                    self.held.append({**ev, "notifiers": held})
            targets = loud
        for n in targets:
            self.pool.submit(notify.send, n, ev, self.cfg.title)

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
            row = {"id": c.id, "name": c.name, "group": c.group or ("Sett" if c.source == "sett" else ""),
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
                "errors": self.cfg.errors if full else [],
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
            open_by_id = {i["id"]: n for n, i in enumerate(self.incidents) if i.get("end") is None and "id" in i}
            for cid, d in doc.get("states", {}).items():
                st = State(status=d.get("status", "pending"), since=float(d.get("since", 0)),
                           detail=d.get("detail", ""), alerted=bool(d.get("alerted")),
                           last_reminder=float(d.get("last_reminder", 0)),
                           buckets={int(k): list(v) for k, v in d.get("buckets", {}).items()})
                if st.status == "down":
                    # Still down across a restart: keep the outage open and don't alert again.
                    st.incident = open_by_id.get(cid)
                    st.fails = 10 ** 6
                self.states[cid] = st
            log.info("state: %d checks, %d incidents restored", len(self.states), len(self.incidents))
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as e:
            log.warning("could not read %s: %s", self.state_file, e)


def about(c: Check) -> str:
    """How to word an alert: "service" (is down / back up), "host" (stopped
    reporting), or "problem" (a disk, a certificate, a failing drive: something wrong, not something gone)."""
    if c.source == "agent":
        return "host" if c.key.endswith("/host") else "problem"
    if c.type == "tls" or c.key.startswith("node:"):
        return "problem"
    return "service"


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
