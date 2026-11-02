#!/bin/sh
# Keep Vitals up to date: pull the newest image, and restart only if it changed.
# Run it from cron on the Docker host, e.g. every night at 04:15:
#   15 4 * * * /opt/brock/auto-update.sh >> /var/log/vitals-update.log 2>&1
# Optional: VITALS_DIR (default: this script's folder), VITALS_CHECKIN (a check-in URL from
# Vitals' Checks tab, so Vitals tells you if the nightly update ever stops running).
set -eu
DIR="${VITALS_DIR:-$(cd "$(dirname "$0")" && pwd)}"
cd "$DIR"
# Compare like with like: the full image ID each running container uses, against the full
# ID of the image its compose file now points at (after the pull).
running() { docker compose ps -q | xargs -r docker inspect -f '{{.Image}}' | sort | tr '\n' ' '; }
wanted() { docker compose config --images | xargs -r -n1 docker image inspect -f '{{.Id}}' | sort | tr '\n' ' '; }
docker compose pull -q
if [ "$(running)" != "$(wanted)" ]; then
    docker compose up -d
    docker image prune -f >/dev/null
    msg="updated"
else
    msg="already up to date"
fi
echo "$(date -Is) vitals: $msg"
if [ -n "${VITALS_CHECKIN:-}" ]; then
    # Right after a restart Vitals needs a few seconds before it answers: wait for it (up to a minute).
    health="$(echo "$VITALS_CHECKIN" | sed 's#/api/push/.*#/healthz#')"
    i=0
    until curl -fsS -m 3 "$health" >/dev/null 2>&1 || [ $i -ge 30 ]; do sleep 2; i=$((i + 1)); done
    curl -fsS -m 10 --retry 3 "${VITALS_CHECKIN}?msg=$(echo "$msg" | tr ' ' '+')" >/dev/null || true
fi
