#!/usr/bin/env python3
"""Vitals agent for Linux: reports this machine's disks, memory, temperatures,
failed services and pending updates to a Vitals server every minute.

One file, standard library only. Normally installed by the server's
install script (see the Vitals README); to run it by hand:

    VITALS_SERVER=http://vitals.lan:8098 VITALS_AGENT_TOKEN=... python3 agent.py

VITALS_AGENT_NAME overrides the host name; VITALS_AGENT_EVERY the interval (s).
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request

VERSION = "0.3.1"
UPDATES_EVERY = 6 * 3600     # apt/dnf can be slow; pending updates don't change by the minute

# Filesystems worth watching. Everything else (tmpfs, overlay, proc, squashfs snaps...) is noise.
REAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "vfat", "exfat", "ntfs", "ntfs3",
           "fuseblk", "jfs", "reiserfs", "bcachefs", "nfs", "nfs4", "cifs", "smb3"}


def env(name: str, default: str | None = None) -> str | None:
    """VITALS_<name>, or BROCK_<name> from agents installed before the rename."""
    return os.environ.get(f"VITALS_{name}") or os.environ.get(f"BROCK_{name}") or default


def disks() -> list[dict]:
    out, seen = [], set()
    try:
        with open("/proc/mounts") as f:
            lines = f.read().splitlines()
    except OSError:
        lines = []
    for line in lines:
        parts = line.split()
        if len(parts) < 3:
            continue
        dev, mount, fs = parts[0], parts[1].replace("\\040", " "), parts[2]
        if fs not in REAL_FS or mount.startswith(("/snap/", "/var/lib/docker/", "/run/")):
            continue
        if fs == "zfs" and "/" in dev and mount != "/":
            continue   # a dataset: its pool's root mount already shows the space
        try:
            u = shutil.disk_usage(mount)
        except OSError:
            continue
        if not u.total or (dev, u.total) in seen:
            continue
        seen.add((dev, u.total))
        out.append({"mount": mount, "total": u.total, "free": u.free,
                    "used_pct": round(100 * (u.total - u.free) / u.total, 1)})
    return out


def memory() -> dict | None:
    try:
        info = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                info[k] = int(v.split()[0]) * 1024
        total, avail = info["MemTotal"], info.get("MemAvailable", info.get("MemFree", 0))
        return {"total": total, "used_pct": round(100 * (total - avail) / total, 1)}
    except (OSError, KeyError, ValueError, ZeroDivisionError):
        return None


def temperatures() -> list[dict]:
    """The hottest reading of each sensor chip (hwmon), else thermal zones."""
    out = []
    base = "/sys/class/hwmon"
    try:
        chips = sorted(os.listdir(base))
    except OSError:
        chips = []
    for chip in chips:
        d = os.path.join(base, chip)
        name = _read(os.path.join(d, "name")) or chip
        hottest = None
        try:
            files = os.listdir(d)
        except OSError:
            continue
        for fn in files:
            if fn.startswith("temp") and fn.endswith("_input"):
                v = _read(os.path.join(d, fn))
                if v and v.lstrip("-").isdigit():
                    c = int(v) / 1000
                    if -40 < c < 150 and (hottest is None or c > hottest):
                        hottest = c
        if hottest is not None:
            out.append({"sensor": name, "celsius": round(hottest, 1)})
    if not out:
        base = "/sys/class/thermal"
        try:
            zones = sorted(z for z in os.listdir(base) if z.startswith("thermal_zone"))
        except OSError:
            zones = []
        for z in zones:
            v = _read(os.path.join(base, z, "temp"))
            if v and v.lstrip("-").isdigit():
                out.append({"sensor": _read(os.path.join(base, z, "type")) or z, "celsius": round(int(v) / 1000, 1)})
    return out


def failed_services() -> list[str] | None:
    if not shutil.which("systemctl"):
        return None
    try:
        p = subprocess.run(["systemctl", "list-units", "--type=service", "--state=failed", "--no-legend", "--plain"],
                           capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return [line.split()[0] for line in p.stdout.splitlines() if line.strip()]


def pending_updates() -> int | None:
    """Upgradable packages from the package manager's cached lists (no refresh, no root needed)."""
    try:
        if shutil.which("apt-get"):
            p = subprocess.run(["apt-get", "-s", "-o", "Debug::NoLocking=true", "upgrade"],
                               capture_output=True, text=True, timeout=120)
            return sum(line.startswith("Inst ") for line in p.stdout.splitlines())
        if shutil.which("dnf"):
            p = subprocess.run(["dnf", "-q", "--cacheonly", "check-update"], capture_output=True, text=True, timeout=120)
            return sum(1 for line in p.stdout.splitlines() if line.strip() and not line.startswith(" "))
        if shutil.which("apk"):
            p = subprocess.run(["apk", "-u", "list"], capture_output=True, text=True, timeout=60)
            return sum(1 for line in p.stdout.splitlines() if line.strip())
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def _read(path: str) -> str:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ""


def report(updates: int | None) -> dict:
    up = _read("/proc/uptime").split()
    return {
        "agent": VERSION, "os": "linux", "name": env("AGENT_NAME") or socket.gethostname(),
        "time": time.time(), "uptime": float(up[0]) if up else None,
        "load": os.getloadavg()[0] if hasattr(os, "getloadavg") else None, "cpus": os.cpu_count(),
        "memory": memory(), "disks": disks(), "temps": temperatures(), "failed_services": failed_services(),
        "updates": updates, "reboot_required": os.path.exists("/var/run/reboot-required"),
    }


def send(server: str, token: str, doc: dict) -> dict:
    req = urllib.request.Request(f"{server.rstrip('/')}/api/report", data=json.dumps(doc).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}",
                                          "User-Agent": f"vitals-agent/{VERSION}"})
    with urllib.request.urlopen(req, timeout=20) as r:
        try:
            return json.loads(r.read() or b"{}")
        except ValueError:
            return {}


def update(server: str, token: str, want: str) -> bool:
    """Replace this file with the server's agent and restart into it. Only when the
    download is complete, is Python, and says it is the version the server offered;
    otherwise keep running as we are. Returns False if nothing changed."""
    me = os.path.abspath(__file__)
    try:
        with urllib.request.urlopen(f"{server.rstrip('/')}/agent.py?token={urllib.parse.quote(token)}", timeout=30) as r:
            code = r.read(2 * 1024 * 1024)
        compile(code, me, "exec")
        if f'VERSION = "{want}"'.encode() not in code:
            raise ValueError("downloaded agent isn't the offered version")
        tmp = me + ".new"
        with open(tmp, "wb") as f:
            f.write(code)
        os.chmod(tmp, 0o755)
        os.replace(tmp, me)
    except Exception as e:   # read-only install, server away, bad download: carry on as we are
        print(f"vitals-agent: not updating to {want}: {e}", file=sys.stderr, flush=True)
        return False
    print(f"vitals-agent: updated {VERSION} -> {want}, restarting", file=sys.stderr, flush=True)
    os.execv(sys.executable, [sys.executable, me, *sys.argv[1:]])
    return True


def main() -> int:
    server, token = env("SERVER"), env("AGENT_TOKEN")
    if not server or not token:
        print("set VITALS_SERVER and VITALS_AGENT_TOKEN", file=sys.stderr)
        # (BROCK_SERVER / BROCK_AGENT_TOKEN from before the rename work too)
        return 2
    every = float(env("AGENT_EVERY", "60"))
    once = "--once" in sys.argv
    updates, updates_at = None, 0.0
    tried: dict[str, float] = {}   # version -> when an update to it last failed
    while True:
        if time.monotonic() - updates_at > UPDATES_EVERY or not updates_at:
            updates, updates_at = pending_updates(), time.monotonic()
        doc = report(updates)
        try:
            answer = send(server, token, doc)
            offered = answer.get("agent_version")
            if (offered and offered != VERSION and not once and env("AGENT_NO_UPDATE") is None
                    and time.monotonic() - tried.get(offered, -1e9) > 3600):
                update(server, token, offered)   # only returns if it didn't work
                tried[offered] = time.monotonic()
        except Exception as e:   # the server being away is normal; keep going
            print(f"vitals-agent: could not report: {e}", file=sys.stderr, flush=True)
            if once:
                return 1
        if once:
            print(json.dumps(doc, indent=2))
            return 0
        time.sleep(every)


if __name__ == "__main__":
    sys.exit(main())
