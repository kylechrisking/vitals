#!/bin/sh
# Installs the Brock agent as a systemd service. Served by your Brock server with
# its address and agent token filled in:
#   curl -fsSL "http://brock:8098/install.sh?token=AGENT_TOKEN" | sudo sh
# Uninstall: sudo systemctl disable --now brock-agent && sudo rm -rf /opt/brock-agent \
#            /etc/systemd/system/brock-agent.service /etc/brock-agent.env
set -eu
SERVER="__SERVER__"
TOKEN="__TOKEN__"

if [ "$(id -u)" != 0 ]; then echo "Run this as root (sudo sh)." >&2; exit 1; fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "The agent needs python3. Debian/Ubuntu/Proxmox: apt install python3. Alpine: apk add python3." >&2; exit 1
fi

mkdir -p /opt/brock-agent
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$SERVER/agent.py?token=$TOKEN" -o /opt/brock-agent/agent.py
else
    wget -qO /opt/brock-agent/agent.py "$SERVER/agent.py?token=$TOKEN"
fi
chmod 755 /opt/brock-agent/agent.py

umask 077
cat > /etc/brock-agent.env <<CONF
BROCK_SERVER=$SERVER
BROCK_AGENT_TOKEN=$TOKEN
CONF

if ! command -v systemctl >/dev/null 2>&1; then
    echo "Agent installed in /opt/brock-agent, but there is no systemd here."
    echo "Start it at boot with: env \$(cat /etc/brock-agent.env) python3 /opt/brock-agent/agent.py"
    exit 0
fi

umask 022
cat > /etc/systemd/system/brock-agent.service <<'UNIT'
[Unit]
Description=Brock agent (reports health to Brock)
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/brock-agent.env
ExecStart=/usr/bin/env python3 /opt/brock-agent/agent.py
Restart=always
RestartSec=30
# It only reads: run it as a throwaway unprivileged user with a read-only system.
DynamicUser=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now brock-agent
sleep 2
if systemctl is-active --quiet brock-agent; then
    echo "Brock agent is running and reporting to $SERVER as $(hostname)."
else
    echo "The agent didn't start; see: journalctl -u brock-agent" >&2; exit 1
fi
