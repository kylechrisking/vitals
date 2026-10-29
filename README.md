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

## Hacking on it

```bash
python -m unittest discover -s tests -t .
```

The tests run real checks against local HTTP, TCP and TLS servers, and real
notifiers against a local receiver.

## License

MIT
