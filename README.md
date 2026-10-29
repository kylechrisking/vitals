# Brock

[![tests](https://github.com/kylechrisking/brock/actions/workflows/ci.yml/badge.svg)](https://github.com/kylechrisking/brock/actions/workflows/ci.yml)

A small uptime and alert agent for a homelab or a small office. It checks the
things you care about, tells your phone when one goes down and again when
it's back, and keeps a status page with uptime history.

It's one small container: plain Python, no dependencies, about 30 MB of RAM.

Brock is a companion to [Sett](https://github.com/kylechrisking/sett), the
dashboard that discovers your lab, but it doesn't need it. On its own, you
list what to watch. Pointed at Sett, it also watches everything Sett found,
plus the Proxmox health Sett reads (failing disks, degraded ZFS pools, failed
backups), without you listing any of it.

## What it does

- **Checks:** HTTP (status, and optionally text on the page), TCP ports,
  ping, DNS (optionally "must resolve to this address"), and TLS certificate
  expiry.
- **Host agents** for Linux and Windows: disk space, memory, temperature,
  failed services, pending updates, Defender (see below).
- **Alerts that don't nag:** a check is down only after a few failures in a
  row (you choose how many), you get one alert when it goes down and one
  when it's back ("Plex is back after 12m"), plus optional reminders while
  it stays down.
- **Where alerts go:** ntfy, Gotify, Discord, Slack (and anything that takes
  Slack webhooks, like Mattermost), email, or any webhook as JSON.
- **Quiet hours:** alerts overnight are held and sent as one summary in the
  morning, saying what's still down. Individual notifiers can opt out.
- **Maintenance windows:** checks keep running, nothing alerts, and planned
  downtime doesn't count against uptime.
- **Status page:** 24-hour, 7, 30 and 90-day uptime, a 30-day bar per check,
  and recent incidents. Private by default (token), or public, in which case
  it shows only the checks you mark public, without addresses or error
  messages.
- **When Sett goes away:** you get one "Sett is down" alert, not one for
  every service it was reporting. Restarts of Sett or Brock don't re-send
  alerts for outages that are already known.

## The settings page

Open `http://brock:8098/settings?token=<your token>`. Everything there is
saved to the data folder and used straight away; `brock.toml` keeps working
underneath it.

- **Notifications:** add Discord, ntfy, Gotify, Slack, email or webhook
  notifiers, tick which alerts each one gets, limit one to certain hosts or
  checks, set its message format, and send a test.
- **Sites:** a group of hosts and services that share a network, power or a
  job (everything on one UPS, or the media stack). A site is down only when
  enough of its members are down *at the same time*, so one PC rebooting
  isn't an outage. Tick "Only site is down" on a notifier and it gets just
  `HomeLab at 203.0.113.7 is DOWN` and `... is back UP`.
- **Hosts:** disk, temperature, memory and update limits for every agent, or
  for one host; ignore a disk or a service; never alert for a host.
- **Checks:** mute any check (it's still checked and shown), add or remove
  your own.
- **Quiet hours** and reminders.
- **Activity:** every alert Brock raised, and where it went, including the
  ones that went nowhere.

A problem like a full disk has to look fine twice in a row before it's "OK
again", so a value sitting at the limit doesn't alert every other minute.

## Host agents

A small agent on each machine reports what you can't see from outside:

- disk space on every drive, memory, CPU temperature
- failed systemd services, or Windows services that crashed
- pending updates and a pending reboot
- on Windows, whether Defender's real-time protection is on

Each host becomes a few checks ("pve1", "pve1 · disk", "pve1 · services"...)
with the same alerts, quiet hours and uptime as everything else. If a host
stops reporting, you get "pve1 stopped reporting".

Turn agents on by giving Brock an agent token (letters, digits and
`- _ . ~ + / =`; keep it in the secrets file):

```toml
[agents]
token = "a-long-random-string"
```

Then on each machine, one line:

**Linux** (Proxmox nodes, LXCs, VMs, a Pi; needs python3, which Debian,
Ubuntu and Proxmox already have):

```bash
curl -fsSL "http://brock.lan:8098/install.sh?token=a-long-random-string" | sudo sh
```

It installs a systemd service that runs as an unprivileged throwaway user
with a read-only view of the system.

**Windows**, in PowerShell run as Administrator:

```powershell
irm "http://brock.lan:8098/install.ps1?token=a-long-random-string" | iex
```

It installs a startup task that runs as SYSTEM, with nothing else to
install. The folder holding the token is readable by SYSTEM and
Administrators only.

Thresholds (disk 90%, temperature 85°C by default) and per-host overrides
are under `[agents]` in [brock.example.toml](brock.example.toml).

## Install

```bash
mkdir brock && cd brock
curl -fsSLO https://raw.githubusercontent.com/kylechrisking/brock/main/compose.example.yaml
curl -fsSL -o config/brock.toml --create-dirs https://raw.githubusercontent.com/kylechrisking/brock/main/brock.example.toml
# edit config/brock.toml: what to watch, where to send alerts, a page token
docker compose -f compose.example.yaml up -d
```

Open `http://<that-machine>:8098/?token=<your token>` once; a cookie keeps
you signed in after that.

Run it somewhere other than the things it watches if you can, so it can
still tell you when that machine goes down. A Raspberry Pi works well.

### With Sett

If Sett has sign-in turned on, give Brock an API token there:

```toml
# Sett's secrets file
[auth]
api_tokens = { brock = "a-long-random-string" }
```

and point Brock at it:

```toml
# Brock's brock.toml
[sett]
url = "http://sett.lan:8099"
token = "a-long-random-string"
```

Leave things out with `exclude = ["flaresolverr", "Links"]` (app ids, names
or categories).

### Trying it out

```bash
docker exec brock python -m brock check         # run every check once, now
docker exec brock python -m brock test-notify   # send a test alert everywhere
```

### Without Docker

Python 3.11 or newer, nothing to install:

```bash
git clone https://github.com/kylechrisking/brock && cd brock
BROCK_CONFIG=./brock.toml BROCK_DATA=./data python -m brock
```

## Settings

[brock.example.toml](brock.example.toml) has every setting with comments.
Passwords and tokens can go in a second file, `/secrets/brock.toml`, which
takes the same `[tokens]`, `[sett]` and `[[notify]]` tables; notifier
settings are matched by `name`.

| Variable | Default | |
| --- | --- | --- |
| `BROCK_CONFIG` | `/config/brock.toml` | the config file |
| `BROCK_SECRETS` | `/secrets/brock.toml` | the secrets file |
| `BROCK_DATA` | `/data` | uptime history and incidents |
| `BROCK_PORT` | `8098` | the status page |
| `BROCK_SETT_URL`, `BROCK_SETT_TOKEN` | | instead of `[sett]` |
| `BROCK_NTFY_URL` | | a quick ntfy notifier without a config |

`/api/status` returns everything the page shows, as JSON, for your own
scripts. `/healthz` answers `ok`.

## What's next

- Remote management: patching, installing software and a remote shell on
  the machines the agent runs on, so Brock can fully replace Action1.

## Hacking on it

```bash
python -m unittest discover -s tests -t .
```

The tests run real checks against local HTTP, TCP and TLS servers, and real
notifiers against a local receiver.

## License

MIT
