"""Settings made on the /settings page, kept in <data>/settings.json and
layered over vitals.toml, which stays the base and still works on its own.

    notifiers   notifiers added on the page (type, url, token...)
    routing     per notifier (page or config file): enabled, which events, only-for, message format
    agents      thresholds for every host, and per host
    checks      checks added on the page
    muted       check ids that never notify (still shown, still in the activity log)
    sites       named groups of checks that are "down" only when enough of them are down together
    quiet       {"hours": "23:00-07:00"}
    remind_every

Secrets (webhook URLs, tokens, passwords) never go back to the browser in
full: they come back masked, and a masked value sent back means "unchanged".
"""
from __future__ import annotations

import json
import os
import re
import secrets
from pathlib import Path

from .config import CHECK_TYPES, NOTIFY_TYPES, Check, Config, data_dir

EVENTS = ("site", "host", "service", "problem", "reminder", "digest", "weekly")
EVENT_LABELS = {"site": "Sites going down / back up (several members down together)",
                "host": "Hosts going offline / back online", "service": "Services going down / back up",
                "problem": "Problems: disk, temperature, services, Defender, updates, certificates",
                "reminder": "Still-down reminders", "digest": "Summary after quiet hours",
                "weekly": "Weekly summary (Monday 09:00): uptime, outages, hosts"}
FIELDS = ("name", "address", "status", "detail", "duration", "group", "title", "time")
SECRET_KEYS = ("url", "token", "password")
NOTIFIER_KEYS = {"name", "type", "url", "token", "user", "password", "priority", "click", "username", "host", "port",
                 "from", "to", "starttls"}
ROUTE_KEYS = {"enabled", "events", "only", "format", "ignore_quiet"}
AGENT_KEYS = {"every", "missed", "disk_above", "disk_days", "memory_above", "temp_above", "updates_above", "services", "defender",
              "ignore_mounts", "ignore_services", "public"}
MASK = "••••"
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def path() -> Path | None:
    d = data_dir()
    return d / "settings.json" if d else None


def load_doc() -> dict:
    p = path()
    if not p or not p.is_file():
        return {}
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
        return doc if isinstance(doc, dict) else {}
    except (OSError, ValueError):
        return {}


def save_doc(doc: dict) -> None:
    p = path()
    if not p:
        raise OSError("no writable data folder: mount /data to keep settings")
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)   # it holds webhook URLs and tokens
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
    os.replace(tmp, p)


# ---- first run: tokens nobody had to make up ------------------------------------------

def ensure_tokens(cfg: Config) -> dict:
    """Without [tokens] or an [agents] token in the config, Vitals makes its own on
    first start and keeps them in <data>/tokens.json (mode 600), so the page and
    the agents work without editing a file. Returns the ones it made up."""
    d = data_dir()
    if not d:
        return {}
    f = d / "tokens.json"
    try:
        made = json.loads(f.read_text(encoding="utf-8")) if f.is_file() else {}
    except (OSError, ValueError):
        made = {}
    changed = False
    for key in ("page", "agent", "push"):
        if not made.get(key):
            made[key] = secrets.token_urlsafe(24)
            changed = True
    if changed:
        fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(made, fh)
    used = {}
    cfg.push_secret = made["push"]
    if not cfg.tokens:
        cfg.tokens = {"page": made["page"]}
        used["page"] = made["page"]
    if not cfg.agents.get("token"):
        cfg.agents["token"] = made["agent"]
        used["agent"] = made["agent"]
    return used


# ---- applying: vitals.toml + settings.json -> the config Vitals runs on -------------------

def apply(cfg: Config, doc: dict) -> Config:
    routing = doc.get("routing") or {}
    for n in cfg.notifiers:
        n["source"] = "config"
        n.update({k: v for k, v in (routing.get(n["name"]) or {}).items() if k in ROUTE_KEYS})
    names = {n["name"] for n in cfg.notifiers}
    for n in doc.get("notifiers") or []:
        if n.get("name") in names:
            cfg.errors.append(f"settings: notifier {n['name']!r} also exists in vitals.toml; the page's copy is ignored")
            continue
        cfg.notifiers.append({**n, "source": "settings"})
        names.add(n["name"])

    a = doc.get("agents") or {}
    hosts = {**(cfg.agents.get("hosts") or {})}
    for h, o in (a.get("hosts") or {}).items():
        hosts[h] = {**hosts.get(h, {}), **o}
    cfg.agents = {**cfg.agents, **{k: v for k, v in a.items() if k in AGENT_KEYS}, "hosts": hosts}

    if doc.get("quiet") is not None:
        cfg.quiet = doc["quiet"]
    if doc.get("remind_every") is not None:
        cfg.remind_every = float(doc["remind_every"])
    cfg.muted = set(doc.get("muted") or [])
    have_sites = {s["name"] for s in cfg.sites}
    cfg.sites += [s for s in doc.get("sites") or [] if s.get("name") not in have_sites]

    cfg.maintenance = list(cfg.maintenance) + [w for w in doc.get("maintenance") or [] if isinstance(w, dict)]

    have = {c.name for c in cfg.checks}
    for d in doc.get("checks") or []:
        if d.get("name") in have:
            continue
        cfg.checks.append(Check(name=d["name"], type=d["type"], target=d["target"], every=float(d.get("every", 60)),
                                fail_after=int(d.get("fail_after", 3)), group=d.get("group", ""),
                                contains=d.get("contains", ""), expect=d.get("expect", ""),
                                warn_days=int(d.get("warn_days", 14)), public=bool(d.get("public", True)),
                                grace=float(d.get("grace", 0)), token=str(d.get("token") or "")))
        have.add(d["name"])
    return cfg


# ---- validating what the page sends ------------------------------------------------------

class Invalid(ValueError):
    pass


def clean(new: dict, old: dict) -> dict:
    """Check and tidy a settings document from the page. Masked secrets are
    replaced by the stored value they stand for. Raises Invalid with a message
    a person can act on."""
    if not isinstance(new, dict):
        raise Invalid("expected a settings object")
    out: dict = {}
    old_n = {n.get("name"): n for n in old.get("notifiers") or []}
    seen = set()
    out["notifiers"] = []
    for n in new.get("notifiers") or []:
        name = _name(n.get("name"), "notifier")
        if name in seen:
            raise Invalid(f"two notifiers are called {name!r}")
        seen.add(name)
        if n.get("type") not in NOTIFY_TYPES:
            raise Invalid(f"{name}: pick a type ({', '.join(NOTIFY_TYPES)})")
        d = {k: v for k, v in n.items() if k in NOTIFIER_KEYS | ROUTE_KEYS}
        if isinstance(d.get("to"), str):
            d["to"] = [x.strip() for x in d["to"].split(",") if x.strip()]
        for k in SECRET_KEYS:
            if isinstance(d.get(k), str) and MASK in d[k]:
                d[k] = (old_n.get(name) or old_n.get(n.get("was")) or {}).get(k, "")
        if d["type"] != "email" and not str(d.get("url", "")).startswith(("http://", "https://")):
            raise Invalid(f"{name}: the URL should start with http:// or https://")
        url = str(d.get("url", ""))
        if d["type"] == "discord" and "/api/webhooks/" not in url:
            raise Invalid(f"{name}: that isn't a Discord webhook URL. In Discord: channel settings → Integrations → "
                          "Webhooks → Copy Webhook URL (it contains /api/webhooks/)")
        if d["type"] == "slack" and "hooks.slack.com" in url and "/services/" not in url:
            raise Invalid(f"{name}: a Slack webhook URL looks like https://hooks.slack.com/services/...")
        if d["type"] == "gotify" and not d.get("token"):
            raise Invalid(f"{name}: Gotify needs an app token")
        if d["type"] == "email" and not (d.get("host") and d.get("to")):
            raise Invalid(f"{name}: email needs a server (host) and a recipient (to)")
        out["notifiers"].append(_route(d, name))
    out["routing"] = {_name(k, "notifier"): _route(v, k) for k, v in (new.get("routing") or {}).items()}

    a = new.get("agents") or {}
    out["agents"] = _agent(a, "default")
    out["agents"]["hosts"] = {_name(h, "host"): _agent(o, h) for h, o in (a.get("hosts") or {}).items()
                              if _agent(o, h)}

    q = new.get("quiet") or {}
    hours = str(q.get("hours") or "").strip()
    if hours and not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d\s*-\s*([01]\d|2[0-3]):[0-5]\d", hours):
        raise Invalid("quiet hours look like 23:00-07:00")
    out["quiet"] = {"hours": hours} if hours else {}
    out["remind_every"] = _num(new.get("remind_every", 0), "reminder interval", 0, 10080)
    out["muted"] = sorted({str(x) for x in new.get("muted") or []})

    out["sites"] = []
    site_names = set()
    for s in new.get("sites") or []:
        name = _name(s.get("name"), "site")
        if name in site_names:
            raise Invalid(f"two sites are called {name!r}")
        site_names.add(name)
        members = sorted({str(m) for m in s.get("members") or [] if str(m).strip()})
        if not members:
            raise Invalid(f"site {name}: pick the hosts and services that make it up")
        count = int(_num(s.get("count") or len(members), f"site {name}: how many must be down", 1, len(members)))
        out["sites"].append({"name": name, "address": str(s.get("address") or "").strip()[:100],
                             "members": members, "count": count})

    out["maintenance"] = []
    for i, w in enumerate(new.get("maintenance") or []):
        label = str(w.get("name") or f"window {i + 1}").strip()[:64]
        days = [d for d in w.get("days") or [] if d in DAYS]
        for k in ("from", "to"):
            if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", str(w.get(k) or "")):
                raise Invalid(f"maintenance {label}: times look like 03:00")
        if w["from"] == w["to"]:
            raise Invalid(f"maintenance {label}: start and end are the same")
        out["maintenance"].append({"name": label, "days": days, "from": w["from"], "to": w["to"],
                                   "checks": [str(x) for x in w.get("checks") or [] if str(x).strip()]})

    out["checks"] = []
    names = set()
    for d in new.get("checks") or []:
        name = _name(d.get("name"), "check")
        if name in names:
            raise Invalid(f"two checks are called {name!r}")
        names.add(name)
        if d.get("type") not in CHECK_TYPES:
            raise Invalid(f"{name}: pick a check type ({', '.join(CHECK_TYPES)})")
        target = str(d.get("target") or "").strip()
        if not target and d["type"] != "push":
            raise Invalid(f"{name}: what should it check? (an address, URL or host:port)")
        out["checks"].append({"name": name, "type": d["type"], "target": target,
                              "every": _num(d.get("every", 60), f"{name}: interval", 10, 31 * 86400),
                              "grace": _num(d.get("grace") or 0, f"{name}: grace", 0, 7 * 86400),
                              "fail_after": int(_num(d.get("fail_after", 3), f"{name}: failures", 1, 100)),
                              "group": str(d.get("group") or "")[:40], "contains": str(d.get("contains") or ""),
                              "expect": str(d.get("expect") or ""), "warn_days": int(d.get("warn_days") or 14),
                              "public": bool(d.get("public", True))})
        token = str(d.get("token") or "")
        if token:
            if not re.fullmatch(r"[A-Za-z0-9_-]{6,64}", token):
                raise Invalid(f"{name}: a check-in token is 6-64 letters, digits, - or _")
            out["checks"][-1]["token"] = token
    return out


def _route(d: dict, name: str) -> dict:
    out = {k: v for k, v in d.items() if k not in ROUTE_KEYS}
    out["enabled"] = bool(d.get("enabled", True))
    out["ignore_quiet"] = bool(d.get("ignore_quiet", False))
    ev = d.get("events")
    out["events"] = [e for e in (ev if isinstance(ev, list) else EVENTS) if e in EVENTS]
    out["only"] = [str(x) for x in d.get("only") or [] if str(x).strip()]
    fmt = d.get("format") or {}
    out["format"] = {k: str(v)[:500] for k, v in fmt.items() if k in ("down", "up", "reminder") and str(v).strip()}
    for k, v in out["format"].items():
        bad = set(re.findall(r"\{(\w+)\}", v)) - set(FIELDS)
        if bad:
            raise Invalid(f"{name}: unknown placeholder {{{sorted(bad)[0]}}} (use {', '.join('{'+f+'}' for f in FIELDS)})")
    return out


def _agent(a: dict, who: str) -> dict:
    out = {}
    for k in ("disk_above", "disk_days", "memory_above", "temp_above", "updates_above"):
        if a.get(k) not in (None, ""):
            out[k] = _num(a[k], f"{who}: {k.replace('_', ' ')}", 0, 1000)
    for k in ("every", "missed"):
        if a.get(k) not in (None, ""):
            out[k] = _num(a[k], f"{who}: {k}", 1, 86400)
    for k in ("services", "defender", "public"):
        if a.get(k) is not None:
            out[k] = bool(a[k])
    for k in ("ignore_mounts", "ignore_services"):
        if a.get(k) is not None:
            v = a[k]
            out[k] = [s.strip() for s in (v.split(",") if isinstance(v, str) else v) if str(s).strip()]
    return out


def _name(v, what: str) -> str:
    v = str(v or "").strip()
    if not v or len(v) > 64:
        raise Invalid(f"every {what} needs a name (up to 64 characters)")
    return v


def _num(v, what: str, lo: float, hi: float) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError):
        raise Invalid(f"{what} should be a number") from None
    if not lo <= f <= hi:
        raise Invalid(f"{what} should be between {lo:g} and {hi:g}")
    return f


# ---- what the page sees -------------------------------------------------------------------

def mask(v) -> str:
    v = str(v or "")
    if not v:
        return ""
    if v.startswith(("http://", "https://")):
        head = re.match(r"https?://[^/]+", v).group(0)
        return f"{head}/{MASK}{v[-4:]}" if len(v) > len(head) + 1 else head
    return f"{MASK}{v[-4:]}" if len(v) > 8 else MASK


def notifier_view(n: dict) -> dict:
    d = {k: v for k, v in n.items() if k not in SECRET_KEYS}
    for k in SECRET_KEYS:
        if n.get(k):
            d[k] = mask(n[k])
    d.setdefault("events", list(EVENTS))
    d.setdefault("enabled", True)
    d.setdefault("only", [])
    d.setdefault("format", {})
    return d
