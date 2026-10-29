# Vitals

[![tests](https://github.com/kylechrisking/vitals/actions/workflows/ci.yml/badge.svg)](https://github.com/kylechrisking/vitals/actions/workflows/ci.yml)

A small uptime and alert agent for a homelab or a small office. It checks the
things you care about, tells your phone when one goes down and again when
it's back, and keeps a status page with uptime history.

It's one small container: plain Python, no dependencies, about 30 MB of RAM.

*Vitals used to be called Brock. An existing install keeps working as it is:
`brock.toml`, the `BROCK_*` variables, its data folder and agents that are
already installed are all still read. See [Coming from Brock](#coming-from-brock).*

Vitals is a companion to [Sett](https://github.com/kylechrisking/sett), the
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
- **Check-ins from scheduled jobs:** backups, snapshots, renders. Each gets
  a URL to call when it finishes; if it doesn't check in on time, you hear
  about it. Add `?status=fail` to report a failure yourself.
- **Alerts that don't nag:** a check is down only after a few failures in a
  row (you choose how many), you get one alert when it goes down and one
  when it's back ("Plex is back after 12m"), plus optional reminders while
  it stays down.
- **Where alerts go:** ntfy, Gotify, Discord, Slack (and anything that takes
  Slack webhooks, like Mattermost), email, or any webhook as JSON.
- **Quiet hours:** alerts overnight are held and sent as one summary in the
  morning, saying what's still down. Individual notifiers can opt out.
- **Maintenance windows,** one-off or repeating (every night 03:00-03:30,
  weekdays only...): checks keep running, nothing alerts, and planned
  downtime doesn't count against uptime.
- **Status page:** 24-hour, 7, 30 and 90-day uptime, a 30-day bar per check,
  and recent incidents. Private by default (token), or public, in which case
  it shows only the checks you mark public, without addresses or error
  messages.
- **When Sett goes away:** you get one "Sett is down" alert, not one for
  every service it was reporting. Restarts of Sett or Vitals don't re-send
  alerts for outages that are already known.

## The settings page

Open `http://vitals:8098/settings?token=<your token>`. Everything there is
saved to the data folder and used straight away; `vitals.toml` keeps working
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
- **Activity:** every alert Vitals raised, and where it went, including the
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

Turn agents on by giving Vitals an agent token (letters, digits and
`- _ . ~ + / =`; keep it in the secrets file):

```toml
[agents]
token = "a-long-random-string"
```

Then on each machine, one line:

**Linux** (Proxmox nodes, LXCs, VMs, a Pi; needs python3, which Debian,
Ubuntu and Proxmox already have):

```bash
curl -fsSL "http://vitals.lan:8098/install.sh?token=a-long-random-string" | sudo sh
```

It installs a systemd service that runs as an unprivileged throwaway user
with a read-only view of the system.

**Windows**, in PowerShell run as Administrator:

```powershell
irm "http://vitals.lan:8098/install.ps1?token=a-long-random-string" | iex
```

It installs a startup task that runs as SYSTEM, with nothing else to
install. The folder holding the token is readable by SYSTEM and
Administrators only.

It also puts a dot in the system tray: green when the PC checked in
recently, red when it can't reach Vitals. Right-click it for **Check in
now** (reports straight away), the last check-in time, and **Open Vitals**.
The tray runs as you, with no extra rights, and never sees the agent's token.

Agents keep themselves up to date: when Vitals has a newer agent, each one
downloads it, checks it, swaps it in and restarts. Running an install line
again repairs or updates an agent too.

Vitals also keeps a month of each disk's usage and warns ahead of time when
one is filling: "pve3 · disk: /tank full in ~5 days" (7 days' notice by
default; change it, or turn it off, on the Hosts tab).

Thresholds (disk 90%, temperature 85°C by default) and per-host overrides
are under `[agents]` in [vitals.example.toml](vitals.example.toml).

## Install

```bash
mkdir vitals && cd vitals
curl -fsSLO https://raw.githubusercontent.com/kylechrisking/vitals/main/compose.example.yaml
curl -fsSL -o config/vitals.toml --create-dirs https://raw.githubusercontent.com/kylechrisking/vitals/main/vitals.example.toml
# edit config/vitals.toml: what to watch, where to send alerts, a page token
docker compose -f compose.example.yaml up -d
```

No tokens in your config? Vitals makes its own on first start. Find the link
with `docker logs vitals | grep "first time"`, open it, and a cookie keeps
you signed in after that. The settings page's Hosts tab then has the one-line
agent installs, with your address and agent token already filled in.

Run it somewhere other than the things it watches if you can, so it can
still tell you when that machine goes down. A Raspberry Pi works well.

### With Sett

If Sett has sign-in turned on, give Vitals an API token there:

```toml
# Sett's secrets file
[auth]
api_tokens = { vitals = "a-long-random-string" }
```

and point Vitals at it:

```toml
# Vitals' vitals.toml
[sett]
url = "http://sett.lan:8099"
token = "a-long-random-string"
```

Leave things out with `exclude = ["flaresolverr", "Links"]` (app ids, names
or categories).

### Trying it out

```bash
docker exec vitals python -m vitals check         # run every check once, now
docker exec vitals python -m vitals test-notify   # send a test alert everywhere
```

### Without Docker

Python 3.11 or newer, nothing to install:

```bash
git clone https://github.com/kylechrisking/vitals && cd vitals
VITALS_CONFIG=./vitals.toml VITALS_DATA=./data python -m vitals
```

## Settings

[vitals.example.toml](vitals.example.toml) has every setting with comments.
Passwords and tokens can go in a second file, `/secrets/vitals.toml`, which
takes the same `[tokens]`, `[sett]` and `[[notify]]` tables; notifier
settings are matched by `name`.

| Variable | Default | |
| --- | --- | --- |
| `VITALS_CONFIG` | `/config/vitals.toml` | the config file |
| `VITALS_SECRETS` | `/secrets/vitals.toml` | the secrets file |
| `VITALS_DATA` | `/data` | uptime history and incidents |
| `VITALS_PORT` | `8098` | the status page |
| `VITALS_SETT_URL`, `VITALS_SETT_TOKEN` | | instead of `[sett]` |
| `VITALS_NTFY_URL` | | a quick ntfy notifier without a config |

`/api/status` returns everything the page shows, as JSON, for your own
scripts. `/healthz` answers `ok`.

## What's next

- Remote management: patching, installing software and a remote shell on
  the machines the agent runs on, so Vitals can fully replace Action1.

## Moving over from Uptime Kuma

```bash
docker run --rm -v /path/to/uptime-kuma/data:/kuma:ro -v ./data:/data \
  ghcr.io/kylechrisking/vitals python -m vitals import-kuma /kuma/kuma.db --dry-run
```

Drop `--dry-run` to do it. (Stop Kuma first, or point it at a copy of
`kuma.db`; a 1.x "Export Backup" `.json` works too.) HTTP, keyword, port,
ping, DNS and push monitors become checks on the settings page, with their
names, intervals, retries and groups. Push monitors keep their tokens, and
Vitals answers the same `/api/push/<token>` URL, so a job that pinged Kuma
only needs the host in its URL changed. Monitor kinds Vitals doesn't do
(databases, Docker, MQTT...) are listed and left out.

## Coming from Brock

1. Rename the repository on GitHub to `vitals` (Settings → Repository name).
   GitHub redirects the old address, and the image is then published as
   `ghcr.io/kylechrisking/vitals`.
2. In your compose file, change the image to `ghcr.io/kylechrisking/vitals:latest`
   (and `container_name` if you like), then `docker compose up -d`. Keep the same
   `config`, `secrets` and `data` folders: `brock.toml` and everything in `/data`
   are picked up as they are.
3. Agents already installed keep reporting. To get the tray icon and
   self-updates, run the install line from the Hosts tab once on each machine;
   it removes the old Brock agent first.

## Hacking on it

```bash
python -m unittest discover -s tests -t .
```

The tests run real checks against local HTTP, TCP and TLS servers, and real
notifiers against a local receiver.

## License

MIT
