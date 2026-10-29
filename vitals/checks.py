"""The checks themselves. Each takes a Check and returns a Result; none raises."""
from __future__ import annotations

import os
import re
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse

from . import __version__
from .config import Check

USER_AGENT = f"vitals/{__version__}"

_insecure = ssl.create_default_context()
_insecure.check_hostname = False
_insecure.verify_mode = ssl.CERT_NONE


@dataclass
class Result:
    ok: bool
    detail: str = ""
    latency_ms: int | None = None


def run(c: Check) -> Result:
    fn = {"http": http, "tcp": tcp, "ping": ping, "dns": dns, "tls": tls}.get(c.type)
    if fn is None:
        return Result(False, f"unknown check type {c.type!r}")
    try:
        return fn(c)
    except Exception as e:   # a check never takes the agent down
        return Result(False, f"{type(e).__name__}: {e}"[:200])


def _ms(t0: float) -> int:
    return int((time.monotonic() - t0) * 1000)


def http(c: Check) -> Result:
    """GET the URL. Self-signed certificates are fine (use a tls check for expiry).
    Up means a status in expect_status, or any status below 400 when that is empty."""
    url = c.target if "://" in c.target else f"http://{c.target}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_insecure))
    t0 = time.monotonic()
    try:
        with opener.open(req, timeout=c.timeout) as r:
            status, body = r.status, r.read(256 * 1024)
    except urllib.error.HTTPError as e:
        status, body = e.code, (e.read(256 * 1024) if e.fp else b"")
    except urllib.error.URLError as e:
        return Result(False, str(e.reason)[:200])
    ms = _ms(t0)
    good = status in c.expect_status if c.expect_status else status < 400
    if not good:
        return Result(False, f"HTTP {status}", ms)
    if c.contains and c.contains.encode() not in body:
        return Result(False, f"HTTP {status}, but the page doesn't contain {c.contains!r}", ms)
    return Result(True, f"HTTP {status}", ms)


def _host_port(target: str, default: int | None = None) -> tuple[str, int]:
    u = urlparse(target if "://" in target else f"x://{target}")
    port = u.port or {"https": 443, "http": 80}.get(u.scheme) or default
    if not u.hostname or not port:
        raise ValueError(f"{target!r} needs a host and a port")
    return u.hostname, port


def tcp(c: Check) -> Result:
    host, port = _host_port(c.target)
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=c.timeout):
            return Result(True, f"port {port} open", _ms(t0))
    except OSError as e:
        return Result(False, f"port {port}: {e.strerror or e}")


_RTT = re.compile(r"time[=<]\s*([\d.]+)\s*ms")


def ping(c: Check) -> Result:
    """One ICMP echo through the system ping (busybox or iputils), so Vitals
    needs no raw-socket privileges of its own."""
    host = c.target.split("://")[-1].split("/")[0]
    cmd = ["ping", "-c", "1", "-W", str(max(1, int(c.timeout))), host]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=c.timeout + 2)
    except FileNotFoundError:
        return Result(False, "no ping command in this environment; use a tcp check instead")
    except subprocess.TimeoutExpired:
        return Result(False, "no reply")
    if p.returncode != 0:
        return Result(False, "no reply")
    m = _RTT.search(p.stdout)
    ms = round(float(m.group(1))) if m else None
    return Result(True, f"reply in {m.group(1)} ms" if m else "reply", ms)


def dns(c: Check) -> Result:
    """Resolve a name with the system resolver; with `expect`, that address must be among the answers."""
    t0 = time.monotonic()
    try:
        infos = socket.getaddrinfo(c.target, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return Result(False, f"does not resolve: {e.strerror or e}")
    addrs = sorted({i[4][0] for i in infos})
    ms = _ms(t0)
    if c.expect and c.expect not in addrs:
        return Result(False, f"resolves to {', '.join(addrs)}, not {c.expect}", ms)
    return Result(True, ", ".join(addrs[:4]), ms)


def tls(c: Check) -> Result:
    """Days until the certificate on host:port (default 443) expires. Fails
    when it is under warn_days, so the alert comes with time to renew."""
    host, port = _host_port(c.target, 443)
    t0 = time.monotonic()
    with socket.create_connection((host, port), timeout=c.timeout) as sock:
        with _insecure.wrap_socket(sock, server_hostname=host) as s:
            der = s.getpeercert(binary_form=True)
    ms = _ms(t0)
    not_after = cert_not_after(der)
    if not_after is None:
        return Result(False, "could not read the certificate", ms)
    days = int((not_after - time.time()) // 86400)
    if days < 0:
        return Result(False, "certificate has expired", ms)
    if days < c.warn_days:
        return Result(False, f"certificate expires in {days} days", ms)
    return Result(True, f"certificate valid for {days} days", ms)


def cert_not_after(der: bytes | None) -> float | None:
    """notAfter of a DER certificate as a Unix time, using the ssl module's own
    decoder (it reads a PEM file), so there is no dependency on a crypto library."""
    if not der:
        return None
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(pem)
        info = ssl._ssl._test_decode_cert(path)   # noqa: SLF001 (stable since Python 3.0)
        return ssl.cert_time_to_seconds(info["notAfter"])
    except (OSError, ValueError, KeyError, AttributeError):
        return None
    finally:
        os.unlink(path)
