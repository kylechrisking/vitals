"""Where alerts go. Every notifier is a [[notify]] table with a name and a type:

    ntfy     url = "https://ntfy.sh/topic"   token / user+password optional, priority = 5
    gotify   url = "https://gotify.lan"      token = "app token"
    discord  url = "https://discord.com/api/webhooks/..."
    slack    url = "https://hooks.slack.com/services/..."   (Mattermost and Rocket.Chat accept this too)
    webhook  url = "https://..."              the event as JSON; headers = { ... } optional
    email    host, port = 587, user, password, from, to = ["you@x"], starttls = true

Credentials can sit in the secrets file under a [[notify]] with the same name.
A failed send is retried three times; it never stops monitoring.
"""
from __future__ import annotations

import base64
import json
import logging
import smtplib
import ssl
import time
import urllib.error
import urllib.request
from email.message import EmailMessage

from . import __version__

log = logging.getLogger(__name__)
RETRIES = (2, 10, 30)


def message(ev: dict, title: str) -> tuple[str, str]:
    """(subject, body) in plain words."""
    from .monitor import fmt_duration
    k = ev["kind"]
    about = ev.get("about", "service")
    if about == "problem" and k in ("down", "up", "reminder"):
        if k == "down":
            return f"🔴 {ev['check']}: {ev.get('detail') or 'problem'}", f"{ev['check']}: {ev.get('detail') or 'problem'}."
        if k == "up":
            return f"🟢 {ev['check']} is OK again", f"{ev['check']} is OK again after {fmt_duration(ev.get('down_for', 0))}."
        return (f"🔴 {ev['check']}: still {ev.get('detail') or 'a problem'}",
                f"{ev['check']} has had this problem for {fmt_duration(ev.get('down_for', 0))}: {ev.get('detail')}.")
    if about == "host" and k == "down":
        return f"🔴 {ev['check']} stopped reporting", f"{ev['check']} hasn't reported in: {ev.get('detail') or 'no report'}."
    if about == "host" and k == "up":
        return f"🟢 {ev['check']} is reporting again", f"{ev['check']} is back after {fmt_duration(ev.get('down_for', 0))}."
    if k == "down":
        return f"🔴 {ev['check']} is down", f"{ev['check']} stopped answering: {ev.get('detail') or 'no reply'}."
    if k == "up":
        return f"🟢 {ev['check']} is back up", f"{ev['check']} is back after {fmt_duration(ev.get('down_for', 0))}."
    if k == "reminder":
        return (f"🔴 {ev['check']} is still down",
                f"{ev['check']} has been down for {fmt_duration(ev.get('down_for', 0))}: {ev.get('detail') or 'no reply'}.")
    if k == "digest":
        lines = []
        for e in ev["events"]:
            s, _ = message(e, title)
            lines.append(f"{time.strftime('%H:%M', time.localtime(e['at']))}  {s}")
        still = ev.get("still_down") or []
        head = f"Still down: {', '.join(still)}" if still else "Everything that went down has recovered."
        return f"{title}: {len(ev['events'])} alerts during quiet hours", head + "\n\n" + "\n".join(lines)
    if k == "test":
        return f"{title}: test alert", "If you can read this, Brock can reach you here."
    return f"{title}: {k}", json.dumps(ev)


def send(n: dict, ev: dict, title: str = "Brock") -> bool:
    for attempt, wait in enumerate((0, *RETRIES)):
        if wait:
            time.sleep(wait)
        try:
            SENDERS[n["type"]](n, ev, title)
            log.info("notify %s: %s %s", n["name"], ev["kind"], ev.get("check", ""))
            return True
        except Exception as e:
            log.warning("notify %s failed (attempt %d): %s", n["name"], attempt + 1, e)
    return False


def _post(url: str, body: bytes, headers: dict, timeout: float = 15) -> None:
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"User-Agent": f"brock/{__version__}", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        if r.status >= 300:
            raise RuntimeError(f"HTTP {r.status}")


def _json(url: str, obj, headers: dict | None = None) -> None:
    _post(url, json.dumps(obj).encode(), {"Content-Type": "application/json", **(headers or {})})


def _priority(ev: dict, n: dict) -> int:
    return int(n.get("priority", 5)) if ev["kind"] in ("down", "reminder") else 3


def ntfy(n: dict, ev: dict, title: str) -> None:
    subject, body = message(ev, title)
    headers = {"Title": _header_safe(subject),
               "Priority": str(_priority(ev, n)),
               "Tags": {"down": "rotating_light", "reminder": "rotating_light", "up": "white_check_mark"}.get(ev["kind"], "bell")}
    if n.get("token"):
        headers["Authorization"] = f"Bearer {n['token']}"
    elif n.get("user"):
        headers["Authorization"] = "Basic " + base64.b64encode(f"{n['user']}:{n.get('password', '')}".encode()).decode()
    if n.get("click"):
        headers["Click"] = n["click"]
    _post(n["url"], body.encode(), headers)


def _header_safe(s: str) -> str:
    """HTTP headers are Latin-1; ntfy reads RFC 2047 for anything else."""
    try:
        s.encode("latin-1")
        return s
    except UnicodeEncodeError:
        return "=?UTF-8?B?" + base64.b64encode(s.encode()).decode() + "?="


def gotify(n: dict, ev: dict, title: str) -> None:
    subject, body = message(ev, title)
    _json(f"{n['url'].rstrip('/')}/message", {"title": subject, "message": body, "priority": _priority(ev, n)},
          {"X-Gotify-Key": n["token"]})


def discord(n: dict, ev: dict, title: str) -> None:
    subject, body = message(ev, title)
    _json(n["url"], {"content": f"**{subject}**\n{body}"[:2000], "username": n.get("username", "Brock")})


def slack(n: dict, ev: dict, title: str) -> None:
    subject, body = message(ev, title)
    _json(n["url"], {"text": f"*{subject}*\n{body}"})


def webhook(n: dict, ev: dict, title: str) -> None:
    subject, body = message(ev, title)
    _json(n["url"], {**ev, "title": subject, "message": body, "source": title}, n.get("headers"))


def email(n: dict, ev: dict, title: str) -> None:
    subject, body = message(ev, title)
    msg = EmailMessage()
    msg["Subject"], msg["From"] = subject, n.get("from") or n.get("user")
    to = n["to"] if isinstance(n["to"], list) else [n["to"]]
    msg["To"] = ", ".join(to)
    msg.set_content(body)
    port = int(n.get("port", 587))
    ctx = ssl.create_default_context()
    if port == 465:
        server = smtplib.SMTP_SSL(n["host"], port, timeout=20, context=ctx)
    else:
        server = smtplib.SMTP(n["host"], port, timeout=20)
        if n.get("starttls", True):
            server.starttls(context=ctx)
    with server:
        if n.get("user"):
            server.login(n["user"], n.get("password", ""))
        server.send_message(msg)


SENDERS = {"ntfy": ntfy, "gotify": gotify, "discord": discord, "slack": slack, "webhook": webhook, "email": email}
