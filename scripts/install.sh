#!/usr/bin/env bash
# ==============================================================================
# CyberSentinel &mdash; Linux Cybersecurity Monitoring & Defense Panel Installer
# Production Deployment Automation for Ubuntu, Debian, RHEL, AlmaLinux & Rocky
# ==============================================================================

set -euo pipefail

# Visual formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

TARGET_DIR="/opt/cybersentinel"
SERVICE_NAME="cybersentinel.service"
PORT="${CYBERSENTINEL_PORT:-9090}"
BIND_HOST="${CYBERSENTINEL_HOST:-0.0.0.0}"

echo -e "${CYAN}${BOLD}"
cat << "EOF"
   ______      __              _____            __  _            __
  / ____/_  __/ /_  ___  _____/ ___/___  ____  / /_(_)___  ___  / /
 / /   / / / / __ \/ _ \/ ___/\__ \/ _ \/ __ \/ __/ / __ \/ _ \/ / 
/ /___/ /_/ / /_/ /  __/ /   ___/ /  __/ / / / /_/ / / / /  __/ /  
\____/\__, /_.___/\___/_/   /____/\___/_/ /_/\__/_/_/ /_/\___/_/   
     /____/  Linux Cybersecurity Monitoring & Defense Daemon
EOF
echo -e "${NC}"

# 1. Root Privilege Verification
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR] This installer must be executed as root (or with sudo). Exiting.${NC}"
   exit 1
fi

echo -e "${BLUE}[*] Detecting Linux distribution and package manager...${NC}"

# 2. Package Manager Detection & Dependency Installation
if command -v apt-get &>/dev/null; then
    echo -e "${GREEN}[+] Detected Debian / Ubuntu subsystem.${NC}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip python3-venv nftables iproute2 curl procps >/dev/null
elif command -v dnf &>/dev/null; then
    echo -e "${GREEN}[+] Detected RHEL / AlmaLinux / Rocky / Fedora subsystem (dnf).${NC}"
    dnf install -y -q python3 python3-pip nftables iproute procps-ng curl >/dev/null
elif command -v yum &>/dev/null; then
    echo -e "${GREEN}[+] Detected CentOS / RHEL (yum).${NC}"
    yum install -y -q python3 python3-pip nftables iproute procps-ng curl >/dev/null
else
    echo -e "${YELLOW}[!] Warning: Unknown package manager. Please ensure python3, venv, nftables, and ss are installed.${NC}"
fi

# 3. Setup Installation Directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo -e "${BLUE}[*] Preparing destination directory: ${TARGET_DIR}${NC}"
mkdir -p "${TARGET_DIR}"
mkdir -p "/etc/cybersentinel"

if [[ "${SCRIPT_DIR}" != "${TARGET_DIR}" ]]; then
    echo -e "${BLUE}[*] Syncing files from ${SCRIPT_DIR} to ${TARGET_DIR}...${NC}"
    cp -r "${SCRIPT_DIR}/backend" "${TARGET_DIR}/"
    cp -r "${SCRIPT_DIR}/frontend" "${TARGET_DIR}/"
    cp -r "${SCRIPT_DIR}/config" "${TARGET_DIR}/"
    cp "${SCRIPT_DIR}/requirements.txt" "${TARGET_DIR}/"
    if [[ -d "${SCRIPT_DIR}/scripts" ]]; then
        cp -r "${SCRIPT_DIR}/scripts" "${TARGET_DIR}/"
    fi
fi

# 4. Setup Python Virtual Environment
echo -e "${BLUE}[*] Initializing dedicated Python virtual environment...${NC}"
if [[ ! -d "${TARGET_DIR}/venv" ]]; then
    python3 -m venv "${TARGET_DIR}/venv"
fi

"${TARGET_DIR}/venv/bin/pip" install --upgrade pip -q
echo -e "${BLUE}[*] Installing lightweight daemon dependencies...${NC}"
"${TARGET_DIR}/venv/bin/pip" install -q -r "${TARGET_DIR}/requirements.txt"

# 5. Configuration & Baseline Setup
CONFIG_FILE="/etc/cybersentinel/config.json"
if [[ ! -f "${CONFIG_FILE}" ]]; then
    echo -e "${BLUE}[*] Generating initial configuration at ${CONFIG_FILE}...${NC}"
    RANDOM_TOKEN="$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 24)"
    cat > "${CONFIG_FILE}" << EOF
{
  "server": {
    "host": "${BIND_HOST}",
    "port": ${PORT},
    "auth_enabled": false,
    "admin_token": "${RANDOM_TOKEN}"
  },
  "firewall": {
    "backend": "auto",
    "whitelist": [
      "127.0.0.1",
      "::1",
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16"
    ]
  },
  "alerts": {
    "failed_logins_threshold_1h": 10,
    "bandwidth_spike_mbps": 100,
    "threat_score_high": 65
  },
  "notifications": {
    "enabled": false,
    "discord_webhook_url": "",
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "generic_webhook_url": ""
  },
  "fim": {
    "baseline_file": "/etc/cybersentinel/fim_baseline.json",
    "paths": [
      "/etc/passwd",
      "/etc/shadow",
      "/etc/sudoers",
      "/etc/ssh/sshd_config",
      "/etc/hosts",
      "/etc/crontab",
      "/etc/pam.d/common-auth",
      "/root/.ssh/authorized_keys"
    ]
  }
}
EOF
fi

# 6. Initialize File Integrity Baseline (FIM)
echo -e "${BLUE}[*] Building SHA-256 File Integrity Baseline...${NC}"
"${TARGET_DIR}/venv/bin/python3" -c "
import sys
sys.path.append('${TARGET_DIR}')
from backend.app.modules.persistence import fim_monitor
fim_monitor.create_baseline('System installation baseline snapshot')
" 2>/dev/null || true

# 7. Setup Systemd Service
echo -e "${BLUE}[*] Configuring systemd unit: /etc/systemd/system/${SERVICE_NAME}...${NC}"
cat > "/etc/systemd/system/${SERVICE_NAME}" << EOF
[Unit]
Description=CyberSentinel - Linux Cybersecurity Monitoring & Defense Daemon
Documentation=https://github.com/cybersentinel/cybersentinel
After=network.target network-online.target systemd-journald.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${TARGET_DIR}
Environment=PYTHONUNBUFFERED=1
ExecStart=${TARGET_DIR}/venv/bin/python3 -m uvicorn backend.app.main:app --host ${BIND_HOST} --port ${PORT}
Restart=always
RestartSec=3

CapabilityBoundingSet=CAP_NET_ADMIN CAP_KILL CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_KILL CAP_DAC_READ_SEARCH
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=/etc/cybersentinel ${TARGET_DIR}
NoNewPrivileges=no
KillMode=mixed
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

# 8. Service Health Check
echo -e "${BLUE}[*] Waiting for CyberSentinel daemon startup...${NC}"
sleep 2

HEALTH_CHECK_OK=false
for i in {1..10}; do
    if curl -s "http://127.0.0.1:${PORT}/api/overview" >/dev/null 2>&1; then
        HEALTH_CHECK_OK=true
        break
    fi
    sleep 1
done

if [[ "${HEALTH_CHECK_OK}" == "true" ]]; then
    echo -e "${GREEN}${BOLD}[SUCCESS] CyberSentinel daemon is active and responding on port ${PORT}!${NC}\n"
else
    echo -e "${YELLOW}[!] Warning: Daemon started but healthcheck timed out. Check: journalctl -u ${SERVICE_NAME} -n 20${NC}\n"
fi

# Detect external or public IP for banner
PRIMARY_IP="$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || hostname -I | awk '{print $1}' || echo '127.0.0.1')"

echo -e "${CYAN}========================================================================${NC}"
echo -e "${BOLD}CyberSentinel SOC Panel successfully deployed!${NC}"
echo -e "Access URL:      ${BOLD}${GREEN}http://${PRIMARY_IP}:${PORT}/${NC}"
echo -e "Local Address:   http://127.0.0.1:${PORT}/"
echo -e "Config File:     /etc/cybersentinel/config.json"
echo -e "Service Control: systemctl [status|restart|stop] ${SERVICE_NAME}"
echo -e "Service Logs:    journalctl -u ${SERVICE_NAME} -f"
echo -e "${CYAN}========================================================================${NC}"
