#!/bin/sh
# Installs the Vitals agent as a systemd service. Served by your Vitals server with
# its address and agent token filled in:
#   curl -fsSL "http://vitals:8098/install.sh?token=AGENT_TOKEN" | sudo sh
# Run it again any time to repair or update. It also removes an older brock-agent.
# Uninstall: sudo systemctl disable --now vitals-agent && sudo rm -rf /opt/vitals-agent \
#            /etc/systemd/system/vitals-agent.service /etc/vitals-agent.env && sudo userdel vitals-agent
set -eu
SERVER="__SERVER__"
TOKEN="__TOKEN__"

if [ "$(id -u)" != 0 ]; then echo "Run this as root (sudo sh)." >&2; exit 1; fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "The agent needs python3. Debian/Ubuntu/Proxmox: apt install python3. Alpine: apk add python3." >&2; exit 1
fi

# Before the rename this was brock-agent: take it out first.
if [ -f /etc/systemd/system/brock-agent.service ]; then
    systemctl disable --now brock-agent 2>/dev/null || true
    rm -f /etc/systemd/system/brock-agent.service
    echo "Removed the old brock-agent."
fi
rm -rf /opt/brock-agent /etc/brock-agent.env

# Its own unprivileged user, which owns the agent's folder so it can update itself.
if ! id vitals-agent >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin vitals-agent 2>/dev/null \
        || adduser -S -H -s /sbin/nologin vitals-agent
fi

mkdir -p /opt/vitals-agent
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$SERVER/agent.py?token=$TOKEN" -o /opt/vitals-agent/agent.py
else
    wget -qO /opt/vitals-agent/agent.py "$SERVER/agent.py?token=$TOKEN"
fi
chmod 755 /opt/vitals-agent/agent.py
chown -R vitals-agent /opt/vitals-agent

umask 077
cat > /etc/vitals-agent.env <<CONF
VITALS_SERVER=$SERVER
VITALS_AGENT_TOKEN=$TOKEN
CONF
chown vitals-agent /etc/vitals-agent.env

if ! command -v systemctl >/dev/null 2>&1; then
    echo "Agent installed in /opt/vitals-agent, but there is no systemd here."
    echo "Start it at boot as vitals-agent with: env \$(cat /etc/vitals-agent.env) python3 /opt/vitals-agent/agent.py"
    exit 0
fi

umask 022
cat > /etc/systemd/system/vitals-agent.service <<'UNIT'
[Unit]
Description=Vitals agent (reports this machine's health to Vitals)
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/vitals-agent.env
ExecStart=/usr/bin/env python3 /opt/vitals-agent/agent.py
Restart=always
RestartSec=30
User=vitals-agent
# It only reads the system; the one place it may write is its own folder (to update itself).
ProtectSystem=strict
ReadWritePaths=/opt/vitals-agent
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable vitals-agent >/dev/null
systemctl restart vitals-agent
sleep 2
if systemctl is-active --quiet vitals-agent; then
    echo "Vitals agent is running and reporting to $SERVER as $(hostname)."
else
    echo "The agent didn't start; see: journalctl -u vitals-agent" >&2; exit 1
fi
