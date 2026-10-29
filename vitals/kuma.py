"""Bring monitors over from Uptime Kuma:

    python -m vitals import-kuma /path/to/kuma.db        # Kuma's data folder (stop Kuma first, or copy it)
    python -m vitals import-kuma backup.json             # or a 1.x "Export Backup" file
    ... --dry-run                                        # show what would happen, change nothing

Monitors become checks on the settings page, keeping their names, intervals
and groups. Push monitors keep their tokens, and Vitals answers the same
/api/push/<token> URLs, so a cron job only needs its host changed. Kinds
Vitals doesn't do (databases, Docker, MQTT...) are listed and left out.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from urllib.parse import urlparse

from . import settings

MAPPED = {"http": "http", "keyword": "http", "port": "tcp", "ping": "ping", "dns": "dns", "push": "push"}


def read(path: str) -> list[dict]:
    """Kuma's monitors as plain dicts with Kuma's own (snake_case) field names."""
    p = Path(path)
    if p.suffix.lower() == ".json":
        doc = json.loads(p.read_text(encoding="utf-8"))
        rows = doc.get("monitorList") or []
        camel = {"pushToken": "push_token", "invertKeyword": "invert_keyword", "upsideDown": "upside_down",
                 "maxretries": "maxretries"}
        return [{camel.get(k, k): v for k, v in r.items()} for r in rows]
    con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in con.execute("SELECT * FROM monitor")]
    finally:
        con.close()


def convert(monitors: list[dict]) -> tuple[list[dict], list[str]]:
    """(checks for the settings page, notes about what was left out or changed)."""
    groups = {m.get("id"): m.get("name") for m in monitors if m.get("type") == "group"}
    checks, notes, names = [], [], set()
    for m in monitors:
        kind, name = m.get("type"), str(m.get("name") or "").strip()[:64]
        if kind == "group" or not name:
            continue
        if kind not in MAPPED:
            notes.append(f"{name}: Kuma's {kind!r} monitors have no Vitals equivalent; left out")
            continue
        if not m.get("active", 1):
            notes.append(f"{name}: paused in Kuma; left out")
            continue
        if m.get("upside_down"):
            notes.append(f"{name}: 'upside down' mode isn't supported; left out")
            continue
        if name in names:
            notes.append(f"{name}: a second monitor with this name; left out")
            continue
        c = {"name": name, "type": MAPPED[kind], "group": groups.get(m.get("parent")) or "Uptime Kuma",
             "every": max(10, int(m.get("interval") or 60)),
             "fail_after": max(1, min(10, int(m.get("maxretries") or 0) + 1)), "public": True}
        if kind in ("http", "keyword"):
            c["target"] = m.get("url") or ""
            if kind == "keyword":
                if m.get("invert_keyword"):
                    notes.append(f"{name}: 'keyword must be absent' isn't supported; it now checks the page loads")
                else:
                    c["contains"] = m.get("keyword") or ""
        elif kind == "port":
            c["target"] = f"{m.get('hostname')}:{m.get('port')}"
        elif kind in ("ping", "dns"):
            c["target"] = m.get("hostname") or ""
        elif kind == "push":
            c["target"] = ""
            c["token"] = m.get("push_token") or ""
            c["fail_after"] = 1
        if kind != "push" and (not c["target"] or c["target"].startswith("None")):
            notes.append(f"{name}: no address in Kuma; left out")
            continue
        names.add(name)
        checks.append(c)
    return checks, notes


def main(args: list[str]) -> int:
    paths = [a for a in args if not a.startswith("--")]
    if not paths:
        print(__doc__)
        return 2
    try:
        monitors = read(paths[0])
    except (OSError, ValueError, sqlite3.Error) as e:
        print(f"Can't read {paths[0]}: {e}")
        return 1
    checks, notes = convert(monitors)
    doc = settings.load_doc()
    have = {c.get("name") for c in doc.get("checks") or []}
    new = [c for c in checks if c["name"] not in have]
    for c in checks:
        where = c["target"] or "check-in"
        host = urlparse(where).hostname if "://" in where else where
        print(f"{'skip (exists)' if c['name'] in have else 'add':>13}  {c['type']:<5} {c['name']:<32} {host}")
    for n in notes:
        print(f"         note  {n}")
    if "--dry-run" in args:
        print(f"\nDry run: {len(new)} check(s) would be added.")
        return 0
    if not new:
        print("\nNothing new to add.")
        return 0
    doc["checks"] = (doc.get("checks") or []) + new
    try:
        settings.save_doc(settings.clean(doc, doc))
    except settings.Invalid as e:
        print(f"\nNot saved: {e}")
        return 1
    print(f"\nAdded {len(new)} check(s). Vitals picks them up within a few seconds; see the settings page.")
    pushes = [c for c in new if c["type"] == "push"]
    if pushes:
        print("Push monitors keep their tokens: point their jobs at http://<vitals>:8098/api/push/<same token>.")
    return 0
