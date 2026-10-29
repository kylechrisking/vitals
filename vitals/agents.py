"""Host agents: small scripts on each machine that report disks, memory,
temperatures, failed services, pending updates and Defender's state.

    [agents]
    token = "..."                 # what agents send; better in the secrets file
    every = 60                    # seconds between reports (the agents' default)
    missed = 3                    # reports missed before a host counts as down
    disk_above = 90               # % used, any disk
    memory_above = 0              # % used (0 = don't alert)
    temp_above = 85               # °C, hottest sensor
    services = true               # alert on failed systemd units / crashed Windows services
    updates_above = 0             # alert when more updates than this are waiting (0 = don't)
    defender = true               # alert when Windows Defender real-time protection is off
    ignore_mounts = ["/boot/efi"]
    ignore_services = []
    # server_url = "http://vitals.lan:8098"   # what install scripts tell agents (default: the address you used)

    [agents.hosts.nas]            # any of the above, for one host
    disk_above = 95

Each host becomes a few checks: the host itself (is it reporting?), its
disks, temperature, services and so on. They behave like any other check:
alerts, quiet hours, maintenance windows, uptime.
"""
from __future__ import annotations

import time

from .checks import Result
from .config import Check

DEFAULTS = {"every": 60, "missed": 3, "disk_above": 90, "memory_above": 0, "temp_above": 85, "services": True,
            "updates_above": 0, "defender": True, "ignore_mounts": [], "ignore_services": [], "notify": [],
            "public": False, "fail_after": 2}
AGENT_VERSION = "0.3.1"       # what agent.py and agent.ps1 say; agents that differ update themselves
FORGET_AFTER = 30 * 86400     # a host silent this long is dropped (and stops alerting)
MAX_NAME = 64


def host_conf(agents: dict, name: str) -> dict:
    top = {k: v for k, v in agents.items() if k not in ("hosts", "token", "server_url")}
    return {**DEFAULTS, **top, **((agents.get("hosts") or {}).get(name) or {})}


def clean_name(name) -> str | None:
    name = str(name or "").strip()[:MAX_NAME]
    return name if name and all(c.isalnum() or c in "-_. " for c in name) else None


def _check(host: str, part: str, label: str, conf: dict, fail_after: int | None = None) -> Check:
    # A problem (disk, temperature...) must look fine twice before it's "OK again", so a
    # value sitting right at the limit doesn't send an alert every other minute.
    return Check(name=f"{host}" if not label else f"{host} · {label}", type="agent", target=host,
                 every=float(conf["every"]), fail_after=fail_after or int(conf["fail_after"]), group="Hosts",
                 notify=list(conf.get("notify") or []), public=bool(conf.get("public")), source="agent",
                 key=f"{host}/{part}", recover_after=1 if part == "host" else 2)


def heartbeat(host: str, conf: dict) -> Check:
    return _check(host, "host", "", conf, fail_after=1)   # "missed" already gives it slack


def _num(v) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _list(v) -> list:
    """Windows PowerShell turns a one-item list into the item itself (and an empty one
    into nothing), so a report can say {"mount": "C:"} where a list was meant."""
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def normalize(doc: dict) -> dict:
    """A report in the shape the rest of Vitals expects, whatever the agent's version or
    platform sent: lists are lists, numbers are numbers, nothing missing that's read."""
    d = dict(doc)
    disks = []
    for x in _list(doc.get("disks")):
        if isinstance(x, dict) and x.get("mount") is not None and _num(x.get("used_pct")) is not None:
            disks.append({**x, "mount": str(x["mount"]), "used_pct": _num(x["used_pct"]),
                          "free": _num(x.get("free")), "total": _num(x.get("total"))})
    d["disks"] = disks
    d["temps"] = [{"sensor": str(t.get("sensor", "?")), "celsius": _num(t.get("celsius"))}
                  for t in _list(doc.get("temps")) if isinstance(t, dict) and _num(t.get("celsius")) is not None]
    fs = doc.get("failed_services")
    d["failed_services"] = None if fs is None else [str(s) for s in _list(fs) if s]
    mem = doc.get("memory")
    d["memory"] = ({**mem, "used_pct": _num(mem.get("used_pct"))} if isinstance(mem, dict) else {})
    u = _num(doc.get("updates"))
    d["updates"] = None if u is None else int(u)
    d["uptime"] = _num(doc.get("uptime"))
    d["reboot_required"] = bool(doc.get("reboot_required"))
    if not isinstance(doc.get("defender"), dict):
        d["defender"] = None
    return d


def evaluate(host: str, doc: dict, conf: dict) -> list[tuple[Check, Result]]:
    """The checks for one report and how each came out."""
    out = [(heartbeat(host, conf), Result(True, summary(doc)))]

    disks = [d for d in doc.get("disks") or [] if d.get("mount") not in set(conf["ignore_mounts"])]
    if disks:
        limit = float(conf["disk_above"])
        full = [d for d in disks if float(d.get("used_pct", 0)) > limit]
        worst = max(disks, key=lambda d: float(d.get("used_pct", 0)))
        detail = ", ".join(f"{d['mount']} {d['used_pct']:.0f}% ({_size(d.get('free'))} free)" for d in (full or [worst]))
        out.append((_check(host, "disk", "disk", conf, 1), Result(not full, detail)))

    mem = doc.get("memory") or {}
    if mem.get("used_pct") is not None and float(conf["memory_above"]):
        over = float(mem["used_pct"]) > float(conf["memory_above"])
        out.append((_check(host, "memory", "memory", conf), Result(not over, f"{mem['used_pct']:.0f}% used")))

    temps = doc.get("temps") or []
    if temps:
        hot = max(temps, key=lambda t: float(t.get("celsius", 0)))
        over = float(hot["celsius"]) > float(conf["temp_above"])
        out.append((_check(host, "temp", "temperature", conf), Result(not over, f"{hot['celsius']:.0f}°C ({hot.get('sensor', '?')})")))

    failed = doc.get("failed_services")
    if failed is not None and conf["services"]:
        bad = [s for s in failed if s not in set(conf["ignore_services"])]
        out.append((_check(host, "services", "services", conf),
                    Result(not bad, f"failed: {', '.join(bad[:8])}" + (" ..." if len(bad) > 8 else "") if bad else "all running")))

    updates = doc.get("updates")
    if updates is not None and int(conf["updates_above"]):
        over = int(updates) > int(conf["updates_above"])
        out.append((_check(host, "updates", "updates", conf, 1), Result(not over, f"{updates} waiting")))

    defender = doc.get("defender")
    if isinstance(defender, dict) and conf["defender"]:
        off = defender.get("realtime") is False or defender.get("antivirus") is False
        age = defender.get("signature_age_days")
        detail = "real-time protection is off" if off else f"on, signatures {age} days old" if age is not None else "on"
        out.append((_check(host, "defender", "defender", conf, 1), Result(not off, detail)))
    return out


def summary(doc: dict) -> str:
    """One line for the status page: "C: 72% · RAM 41% · 52°C · 3 updates · reboot pending"."""
    parts = []
    disks = doc.get("disks") or []
    if disks:
        worst = max(disks, key=lambda d: float(d.get("used_pct", 0)))
        parts.append(f"{worst['mount']} {float(worst['used_pct']):.0f}%")
    mem = doc.get("memory") or {}
    if mem.get("used_pct") is not None:
        parts.append(f"RAM {float(mem['used_pct']):.0f}%")
    temps = doc.get("temps") or []
    if temps:
        parts.append(f"{max(float(t['celsius']) for t in temps):.0f}°C")
    if doc.get("updates"):
        parts.append(f"{doc['updates']} update{'s' if doc['updates'] != 1 else ''}")
    if doc.get("reboot_required"):
        parts.append("reboot pending")
    if doc.get("uptime"):
        parts.append(f"up {_uptime(float(doc['uptime']))}")
    return " · ".join(parts)


def missed(last: float, conf: dict, now: float | None = None) -> float | None:
    """Seconds since the last report if the host is overdue, else None."""
    since = (now or time.time()) - last
    return since if since > float(conf["every"]) * float(conf["missed"]) else None


def _size(n) -> str:
    if n is None:
        return "?"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB", "MB") else f"{n:.1f} {unit}"
        n /= 1024
    return ""


def _uptime(s: float) -> str:
    d, h = int(s // 86400), int(s % 86400 // 3600)
    return f"{d}d {h}h" if d else f"{h}h {int(s % 3600 // 60)}m"
