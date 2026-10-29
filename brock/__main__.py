"""python -m brock                    run the agent and its status page
python -m brock check              run every configured check once and print the results
python -m brock test-notify [NAME] send a test alert to every notifier (or one)"""
from __future__ import annotations

import logging
import os
import signal
import sys

from . import checks, config, notify
from .monitor import Monitor
from .server import serve


def main() -> None:
    logging.basicConfig(level=os.environ.get("BROCK_LOG", "INFO").upper(),
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    args = sys.argv[1:]
    cfg = config.load()
    if args[:1] == ["check"]:
        sys.exit(check_once(cfg))
    if args[:1] == ["test-notify"]:
        sys.exit(test_notify(cfg, args[1:]))
    if args[:1] in (["-h"], ["--help"], ["help"]):
        print(__doc__)
        return
    mon = Monitor(cfg)

    def stop(signum, frame):
        mon.save()
        sys.exit(0)
    signal.signal(signal.SIGTERM, stop)
    try:
        serve(mon, cfg.port)
    except KeyboardInterrupt:
        mon.save()


def check_once(cfg: config.Config) -> int:
    if not cfg.checks:
        print("no [[check]] entries in the config")
        return 1
    bad = 0
    for c in cfg.checks:
        r = checks.run(c)
        bad += not r.ok
        ms = f" {r.latency_ms} ms" if r.latency_ms is not None else ""
        print(f"{'ok  ' if r.ok else 'FAIL'}  {c.name:<28} {c.type:<5} {r.detail}{ms}")
    return 1 if bad else 0


def test_notify(cfg: config.Config, names: list[str]) -> int:
    targets = [n for n in cfg.notifiers if not names or n["name"] in names]
    if not targets:
        print("no matching [[notify]] entries")
        return 1
    failed = 0
    for n in targets:
        ok = notify.send(n, {"kind": "test", "at": 0}, cfg.title)
        failed += not ok
        print(f"{'sent' if ok else 'FAILED'}  {n['name']} ({n['type']})")
    return 1 if failed else 0


if __name__ == "__main__":
    main()
