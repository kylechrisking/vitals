"""Config: one TOML file, optional secrets file, reloaded when either changes.

    title = "Home"
    [[check]]
    name = "Router"
    type = "ping"            # http | tcp | ping | dns | tls
    target = "192.168.1.1"

    [sett]                   # optional: watch everything Sett discovered
    url = "http://sett:8099"
    token = "..."            # one of Sett's [auth] api_tokens, if Sett has sign-in

    [[notify]]
    type = "ntfy"
    url = "https://ntfy.sh/my-lab-alerts"

See vitals.example.toml for every setting.
"""
from __future__ import annotations

import logging
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

CHECK_TYPES = ("http", "tcp", "ping", "dns", "tls", "push")   # push: a scheduled job checks in
NOTIFY_TYPES = ("ntfy", "gotify", "discord", "slack", "webhook", "email")


@dataclass
class Check:
    name: str
    type: str
    target: str
    every: float = 60               # seconds between runs
    timeout: float = 10
    fail_after: int = 3             # consecutive failures before it counts as down (and alerts)
    expect_status: list[int] = field(default_factory=list)   # http: [] means any status below 400
    contains: str = ""              # http: body must contain this
    expect: str = ""                # dns: an address the name must resolve to
    warn_days: int = 14             # tls: alert when the certificate expires sooner than this
    grace: float = 0                # push: extra time after `every` before a missed check-in counts (0 = automatic)
    token: str = ""                 # push: the secret part of its check-in URL (default: derived)
    group: str = ""                 # shown on the status page
    notify: list[str] = field(default_factory=list)   # notifier names; [] means all
    public: bool = True             # listed on the public status page
    source: str = "config"          # config | sett
    key: str = ""                   # sett: the service's stable key, so two "Sonarr"s stay apart
    recover_after: int = 1          # successes in a row before it counts as back (problems use 2: no flapping)

    @property
    def id(self) -> str:
        return f"{self.source}:{self.key or self.name}"


@dataclass
class Config:
    title: str = "Status"
    port: int = 8098
    checks: list[Check] = field(default_factory=list)
    notifiers: list[dict] = field(default_factory=list)
    sett: dict = field(default_factory=dict)
    quiet: dict = field(default_factory=dict)            # hours = "23:00-07:00"
    maintenance: list[dict] = field(default_factory=list)  # [[maintenance]] start/end (ISO), checks = [...]
    remind_every: float = 0                              # minutes between "still down" reminders (0 = never)
    public_status: bool = False                          # serve the status page without a token
    tokens: dict = field(default_factory=dict)           # name -> token for /api/* and the page
    agents: dict = field(default_factory=dict)           # [agents] host agents: token, thresholds, per-host overrides
    muted: set = field(default_factory=set)              # check ids that never notify
    push_secret: str = ""                                # derives check-in URLs (kept in tokens.json)
    made_tokens: dict = field(default_factory=dict)      # tokens Vitals made itself (no [tokens] / [agents] token)
    sites: list[dict] = field(default_factory=list)      # [[site]] name, address, members (check ids or names), count
    files: dict[str, float] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)      # problems found while loading, shown on the page


def env(name: str, default: str | None = None) -> str | None:
    """VITALS_<name>, or BROCK_<name> as it was called before the rename."""
    return os.environ.get(f"VITALS_{name}") or os.environ.get(f"BROCK_{name}") or default


def _first(*paths: str) -> Path:
    """The first of these files that exists (vitals.toml, then the older brock.toml), else the first."""
    return next((Path(p) for p in paths if Path(p).is_file()), Path(paths[0]))


def load() -> Config:
    path = Path(env("CONFIG") or _first("/config/vitals.toml", "/config/brock.toml"))
    secrets_path = Path(env("SECRETS") or _first("/secrets/vitals.toml", "/secrets/brock.toml"))
    raw = _read(path)
    secrets = _read(secrets_path)
    cfg = Config(
        title=raw.get("title", "Status"),
        port=int(env("PORT") or raw.get("port", 8098)),
        sett={**raw.get("sett", {}), **secrets.get("sett", {})},
        quiet=raw.get("quiet", {}),
        maintenance=raw.get("maintenance", []),
        remind_every=float(raw.get("remind_every", 0)),
        public_status=bool(raw.get("public_status", False)),
        tokens={**raw.get("tokens", {}), **secrets.get("tokens", {})},
        agents={**raw.get("agents", {}), **secrets.get("agents", {})},
        files={str(path): _mtime(path), str(secrets_path): _mtime(secrets_path)},
    )
    if env("SETT_URL"):
        cfg.sett["url"] = env("SETT_URL")
    if env("SETT_TOKEN"):
        cfg.sett["token"] = env("SETT_TOKEN")

    seen = set()
    for i, d in enumerate(raw.get("check", [])):
        name, kind, target = d.get("name"), d.get("type", "http"), d.get("target") or d.get("url")
        if kind == "push":
            target = target or ""   # nothing to reach: the job calls us
        if not name or (not target and kind != "push") or kind not in CHECK_TYPES:
            cfg.errors.append(f"[[check]] #{i + 1}: needs name, target and a type from {', '.join(CHECK_TYPES)}")
            continue
        if name in seen:
            cfg.errors.append(f"[[check]] {name!r} appears twice; the second one is ignored")
            continue
        seen.add(name)
        expect = d.get("expect_status", [])
        cfg.checks.append(Check(
            name=name, type=kind, target=str(target), every=float(d.get("every", 60)),
            timeout=float(d.get("timeout", 10)), fail_after=max(1, int(d.get("fail_after", 3))),
            expect_status=[int(x) for x in (expect if isinstance(expect, list) else [expect])],
            contains=d.get("contains", ""), expect=d.get("expect", ""), warn_days=int(d.get("warn_days", 14)),
            group=d.get("group", ""), notify=list(d.get("notify", [])), public=bool(d.get("public", True)),
            grace=float(d.get("grace", 0)), token=str(d.get("token", "")),
        ))

    # Notifiers: settings from the config, credentials from the secrets file by the same name.
    secret_notify = {n.get("name"): n for n in secrets.get("notify", []) if n.get("name")}
    for i, d in enumerate(raw.get("notify", []) + [n for n in secrets.get("notify", [])
                                                   if n.get("name") not in {x.get("name") for x in raw.get("notify", [])}]):
        n = {**d, **secret_notify.get(d.get("name"), {})}
        n.setdefault("name", n.get("type", f"notify{i + 1}"))
        if n.get("type") not in NOTIFY_TYPES:
            cfg.errors.append(f"[[notify]] {n['name']!r}: type must be one of {', '.join(NOTIFY_TYPES)}")
            continue
        cfg.notifiers.append(n)
    if env("NTFY_URL"):
        cfg.notifiers.append({"name": "ntfy-env", "type": "ntfy", "url": env("NTFY_URL")})
    cfg.sites = [s for s in raw.get("site", []) if s.get("name") and s.get("members")]
    from . import settings   # the /settings page's changes, layered on top
    sp = settings.path()
    if sp:
        cfg.files[str(sp)] = _mtime(sp)
    settings.apply(cfg, settings.load_doc())
    cfg.made_tokens = settings.ensure_tokens(cfg)
    for e in cfg.errors:
        log.warning("config: %s", e)
    return cfg


def _read(path: Path) -> dict:
    if not path.is_file():
        return {}
    with open(path, "rb") as f:
        return tomllib.load(f)


def _mtime(p: Path) -> float:
    try:
        return p.stat().st_mtime
    except OSError:
        return 0.0


def changed(cfg: Config) -> bool:
    return any(_mtime(Path(f)) != m for f, m in cfg.files.items())


def data_persistent() -> bool:
    """Will the data folder survive a rebuild of the container? True when VITALS_DATA/BROCK_DATA
    was set, or /data is a mounted volume (the image has an empty /data of its own)."""
    d = data_dir()
    if not d:
        return False
    if env("DATA"):
        return True
    return d == Path("/data") and _mounted(d)


def _mounted(path: Path) -> bool:
    """Is `path` a volume or bind mount (so it outlives the container)?"""
    try:
        with open("/proc/self/mountinfo") as f:
            if any(line.split()[4] == str(path) for line in f if len(line.split()) > 4):
                return True
    except OSError:
        pass
    return os.path.ismount(path)


def data_dir() -> Path | None:
    """VITALS_DATA (or BROCK_DATA), else /data when mounted, else a temp folder. None if nothing is writable."""
    for i, c in enumerate([env("DATA"), "/data", "/tmp/vitals"]):
        if not c or (i == 1 and not Path(c).is_dir()):
            continue
        d = Path(c)
        try:
            d.mkdir(parents=True, exist_ok=True)
            (d / ".write-test").write_bytes(b"")
            (d / ".write-test").unlink()
            return d
        except OSError:
            continue
    return None
