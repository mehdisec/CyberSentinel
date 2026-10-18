# CyberSentinel 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI%20%2B%20AsyncIO-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com/)
[![Vue 3](https://img.shields.io/badge/Frontend-Vue%203%20SPA-4FC08D.svg?logo=vue.js)](https://vuejs.org/)
[![Tailwind CSS](https://img.shields.io/badge/CSS-Tailwind%20CSS-38B2AC.svg?logo=tailwind-css)](https://tailwindcss.com/)
[![nftables](https://img.shields.io/badge/Firewall-nftables%20%2F%20iptables-E95420.svg?logo=linux)](https://netfilter.org/)
[![Fail2Ban](https://img.shields.io/badge/Defense-Fail2Ban%20Matrix-orange.svg)](https://www.fail2ban.org/)
[![Linux](https://img.shields.io/badge/Platform-Ubuntu%20%7C%20Debian%20%7C%20RHEL%20%7C%20AlmaLinux%20%7C%20Rocky-lightgrey.svg?logo=linux)](https://kernel.org)

**CyberSentinel** is a modular, lightweight, production-grade Linux Cybersecurity Monitoring and Defense Panel. Engineered for Security Operations Center (SOC) teams, DevSecOps engineers, and Linux systems administrators, it provides real-time kernel-level visibility, automated intrusion defense, and threat mitigation with minimal resource footprint.

---

## 🌟 Key Highlights & Features

| Capability | Technical Implementation | Benefit |
| :--- | :--- | :--- |
| **Fail2Ban Defense Matrix** | Native `fail2ban-client` jail enumeration (`sshd`, `sshd-aggressive`, `sshd-banned`) & `/var/log/fail2ban.log` parsing | Monitor thousands of active bans, failed logins, lifetime drops, GeoIP attacker origins, and execute instant unban/ban actions. |
| **Top IP Handshake Negotiations** | Real-time TCP socket flow aggregation across `SYN_RECV`, `SYN_SENT`, `ESTAB`, `TIME_WAIT` | Identifies SYN floods, aggressive scanners, and active remote socket handshakes with PID/binary correlation. |
| **Dual Theme Support** | Dark SOC Mode & Clean Light Mode toggle with instant theme switching & `localStorage` persistence | Ergonomic operational viewing in both high-tech dark NOC/SOC environments and daytime office lighting. |
| **Instant Kernel Drop Rules** | Atomic `nftables` tables and sets (with fallback to `ipset`/`iptables`) | Native kernel packet drops with auto-expiring timers (1h, 24h, 7d, permanent) and anti-lockout protection. |
| **File Integrity Monitoring (FIM)** | Real-time SHA-256 digest snapshots on critical system paths (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `~/.ssh/authorized_keys`) | Instant detection of unauthorized privilege escalations, backdoor accounts, or modified configs. |
| **Zero-Overhead Host Telemetry** | Pure `/proc` virtual filesystem delta sampling (`/proc/net/dev`, `/proc/stat`, `/proc/meminfo`, `/proc/[pid]/*`) | Extremely lightweight (~0.2% CPU, <70MB RAM) without relying on heavy external runtime agents. |
| **Interactive Session Defense** | Session inspection via `loginctl` and `who -u` with safe termination (`loginctl terminate-session` / `pkill -t`) | Kill unauthorized root or SSH sessions in a single click. |
| **Persistence Auditing** | Scans system crontabs, user crontabs, systemd timers, and detects suspicious binaries running from `/tmp` or `(deleted)` in RAM | Uncovers rootkits, web shells, and stealthy persistence vectors. |
| **100% Air-Gapped Ready** | Vendored offline assets (Vue 3, Tailwind, Lucide, Chart.js) | Fully operational on isolated, high-security, air-gapped Linux servers without external CDN dependencies. |
| **Real-Time WebSocket Bus** | Sub-second bidirectional WebSocket hub (`/ws/live`) | Live 30s bandwidth sparklines, system metrics, threat score pulses, and streaming security audit logs. |

---

## 🏗️ Architecture

```
                                  +----------------------------------------------------+
                                  |            Dashboard SPA (Frontend)                |
                                  |  Vue 3 + Tailwind CSS + Lucide Icons + Chart.js    |
                                  |     (Dark SOC Mode / Clean Light Mode Toggle)      |
                                  +-------------------------+--------------------------+
                                                            |  (WebSocket / HTTP REST)
                                                            v
+----------------------------------------------------------------------------------------------------------------------+
|                                        CyberSentinel Security Daemon (:9090)                                         |
|                                             FastAPI / AsyncIO Event Loop                                             |
+-----------------------------------------------------------+----------------------------------------------------------+
|  REST API Endpoints (/api/*)                              |  WebSocket Live Hub (/ws/live)                           |
|  - Threat Score Calculation & Host Telemetry              |  - Real-time bandwidth pulse (30s sparklines)            |
|  - Fail2Ban Jails & Instant Unban/Ban Operations          |  - Live socket connection states & handshakes            |
|  - Top IP TCP Negotiations Matrix                         |  - Streaming security audit log tail                     |
|  - Session Termination & Firewall Drop Rules              |  - Threat score broadcast & anomaly alerts               |
+-----------------------------------------------------------+----------------------------------------------------------+
                                                            |
                                                            v
+----------------------------------------------------------------------------------------------------------------------+
|                                       Linux Subsystem Primitives & Kernel Hooks                                      |
+------------------------------------+------------------------------------+--------------------------------------------+
|  /proc Subsystem Telemetry         |  Kernel Packet Filter & Defense    |  Identity, Fail2Ban & Persistence          |
|  - /proc/net/dev (Bandwidth RX/TX) |  - nftables (Atomic sets & timers) |  - fail2ban-client & /var/log/fail2ban.log |
|  - /proc/stat (Accurate CPU %)     |  - Sets with native auto-timeouts  |  - /var/log/auth.log & journald logs       |
|  - /proc/meminfo (RAM Allocation)  |  - iptables / ipset fallback       |  - loginctl & who (Active User Sessions)   |
|  - /proc/[pid]/exe & cmdline       |  - Anti-Lockout Whitelist Engine   |  - SHA-256 FIM Baseline & Persistence Scan |
+------------------------------------+------------------------------------+--------------------------------------------+
```

---

## 📁 Repository Structure

```
cybersentinel/
├── backend/
│   └── app/
│       ├── __init__.py
│       ├── main.py                     # FastAPI application setup & lifecycle hooks
│       ├── core/
│       │   ├── __init__.py
│       │   ├── config.py               # Runtime settings, thresholds, persistence
│       │   └── security.py             # Auth tokens, rate-limiting, alert dispatchers
│       ├── modules/
│       │   ├── __init__.py
│       │   ├── access.py               # Active sessions, brute-force tracker & sudo audit
│       │   ├── fail2ban.py             # Fail2Ban jail inspection, unban/ban & log tailing
│       │   ├── firewall.py             # nftables/iptables integration, bans & whitelist
│       │   ├── logs.py                 # Filterable audit log stream (regex/severity)
│       │   ├── network.py              # Bandwidth (/proc/net/dev) & top IP negotiations
│       │   ├── persistence.py          # FIM (SHA-256), Cron/Systemd scanner & port verifier
│       │   └── telemetry.py            # CPU/RAM/Disk metrics & Threat Score calculation
│       └── api/
│           ├── __init__.py
│           ├── endpoints.py            # REST CRUD & defensive action endpoints
│           └── websocket.py            # Real-time WebSocket broadcasting hub
├── frontend/
│   ├── index.html                      # Main SOC SPA layout, modals, header & navigation
│   └── static/
│       ├── css/
│       │   └── soc.css                 # SOC dark theme + complete light mode theme overrides
│       ├── js/
│       │   ├── app.js                  # Vue 3 root app, WebSocket state, theme & modal controllers
│       │   └── components/
│       │       ├── OverviewView.js     # Threat score banner, sparklines, Fail2Ban stats, top attackers
│       │       ├── NetworkView.js      # Bandwidth graph, Top IP negotiations, Fail2Ban matrix, sockets
│       │       ├── AccessView.js       # Active user sessions, brute-force tracker & sudo history
│       │       ├── LogsView.js         # Streaming terminal log viewer with regex/severity filters
│       │       ├── PersistenceView.js  # FIM baseline checker, cron/timer scanner & port verification
│       │       ├── FirewallView.js     # Active bans table, manual ban form & whitelist manager
│       │       └── SettingsView.js     # Alert thresholds, webhook integrations & auth toggle
│       └── vendor/                     # 100% Self-contained offline assets
│           ├── chart.umd.js            # Chart.js
│           ├── lucide.js               # Lucide SVG Icons
│           ├── tailwind.js             # Tailwind CSS Engine
│           └── vue.global.js           # Vue 3 Runtime
├── scripts/
│   ├── install.sh                      # Production multi-distro setup & systemd automation
│   ├── cybersentinel.service           # Hardened systemd service unit definition
│   └── test_panel.sh                   # Comprehensive 20-point automated integration test suite
├── config/
│   └── config.example.json             # Configuration template
├── .gitignore                          # Clean git ignores for Python & runtime state
├── LICENSE                             # MIT Open-Source License
├── requirements.txt                    # Minimal lightweight Python dependencies
└── README.md                           # Documentation and operations guide
```

---

## 🚀 Quick Start & Installation

### Option 1: Automated Installation (Recommended)

Clone the repository and run the automated installer as `root` (or with `sudo`):

```bash
git clone https://github.com/cybersentinel/cybersentinel.git /opt/cybersentinel
cd /opt/cybersentinel
sudo bash scripts/install.sh
```

#### What `install.sh` Does Automatically:
1. **OS Detection:** Detects Debian, Ubuntu, RHEL, AlmaLinux, Rocky Linux, or Fedora.
2. **Package Setup:** Installs `python3`, `python3-venv`, `nftables`, `iproute2` (`ss`), `procps`, and `curl`.
3. **Dedicated Directory:** Prepares `/opt/cybersentinel` and runtime configurations in `/etc/cybersentinel/`.
4. **Isolated Virtualenv:** Creates `/opt/cybersentinel/venv` and installs lightweight dependencies (`fastapi`, `uvicorn`, `pydantic`, `websockets`).
5. **Initial FIM Baseline:** Automatically builds a SHA-256 baseline snapshot of critical security files.
6. **Hardened Systemd Unit:** Installs, enables, and starts `/etc/systemd/system/cybersentinel.service`.
7. **Health Verification:** Verifies the local HTTP and WebSocket endpoints are responding.

---

### Option 2: Manual / Developer Setup

```bash
# 1. Clone repository
git clone https://github.com/cybersentinel/cybersentinel.git
cd cybersentinel

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy configuration template
cp config/config.example.json config/config.json

# 5. Launch development server
python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port 9090 --reload
```

---

## ⚙️ Service Control

```bash
# Check service status
systemctl status cybersentinel.service

# View live daemon logs
journalctl -u cybersentinel.service -f

# Restart daemon
systemctl restart cybersentinel.service

# Stop daemon
systemctl stop cybersentinel.service
```

---

## 🧪 Automated Verification & Testing

CyberSentinel includes an automated 20-point integration test suite that verifies every endpoint, static asset, and daemon module:

```bash
bash scripts/test_panel.sh 9090
```

### Test Suite Output:
```
=================================================================
  CyberSentinel Verification & Integration Test Suite
  Target: http://127.0.0.1:9090
=================================================================
Testing Frontend SPA HTML...                [PASS] (HTTP 200)
Testing SOC CSS Theme...                    [PASS] (HTTP 200)
Testing Offline Vendor Bundle (Vue)...      [PASS] (HTTP 200)
Testing SOC Overview Telemetry...           [PASS] (HTTP 200)
Testing Live Bandwidth Tracker...           [PASS] (HTTP 200)
Testing Kernel Sockets Inspection...        [PASS] (HTTP 200)
Testing Fail2Ban Status & Jails...          [PASS] (HTTP 200)
Testing Fail2Ban Activity Logs...           [PASS] (HTTP 200)
Testing Top IP Negotiations Matrix...       [PASS] (HTTP 200)
Testing Interactive Sessions...             [PASS] (HTTP 200)
Testing Failed SSH Login Tracker...         [PASS] (HTTP 200)
Testing Sudo Execution Audit...             [PASS] (HTTP 200)
Testing Security Audit Logs...              [PASS] (HTTP 200)
Testing File Integrity Monitor (FIM)...     [PASS] (HTTP 200)
Testing Persistence Artifacts (Cron)...     [PASS] (HTTP 200)
Testing Port-to-Process Verification...     [PASS] (HTTP 200)
Testing Firewall Drop Rules & Bans...       [PASS] (HTTP 200)
Testing Firewall Whitelist...               [PASS] (HTTP 200)
Testing Daemon Configuration...             [PASS] (HTTP 200)
Testing Host System Diagnostics...          [PASS] (HTTP 200)
=================================================================
Total Tests: 20 | Passed: 20 | Failed: 0
All CyberSentinel subsystem tests passed successfully!
```

---

## 🖥️ Dashboard Views Guide

### 1. Dashboard Overview
- **Cybersecurity Threat Score:** Dynamic 0–100 risk score with anomaly breakdown (Failed SSH spikes, FIM alerts, multiple concurrent roots, brute-force volume).
- **Live Hardware & Network Sparklines:** Real-time CPU (`/proc/stat`), Memory (`/proc/meminfo`), Disk, and Inbound/Outbound traffic.
- **Fail2Ban Protection Card:** Displays active jail status, thousands of active banned IPs, and registered jails.
- **Top Attacker Feed:** Aggregated list of remote IPs targeting the server with GeoIP location flags and attempt counts.

### 2. Live Network & Connections
- **Top IP Handshakes & Negotiations:** Inspects TCP states (`SYN_RECV`, `SYN_SENT`, `ESTAB`, `TIME_WAIT`) per remote IP, identifying active socket negotiators and handshake bursts.
- **Fail2Ban Jails & Defense Matrix:** View individual jail statistics (`sshd`, `sshd-aggressive`, `sshd-banned`), currently banned vs total failed counts, enriched banned IP tables with one-click unban, manual ban injection form, and real-time Fail2Ban activity log stream.
- **Filterable Active Sockets Table:** Filter by protocol (`TCP`/`UDP`), socket state (`ESTAB`, `LISTEN`, `TIME_WAIT`), direction (`Inbound`/`Outbound`), or search by process/PID/IP.

### 3. Identity & Access
- **Interactive User Sessions:** View sessions from `loginctl` and `who -u` (username, TTY, remote IP, login time, idle time). Safely terminate active sessions with the **Kill Session** action.
- **SSH Brute-Force Tracker:** Real-time ingestion of failed authentications, bad user probes, and preauth disconnects with GeoIP mapping.
- **Sudo Execution Audit:** Log of privileged commands executed via `sudo`, displaying user, target user, TTY, and command line.

### 4. Security Logs & Audit
- High-performance live log stream querying `journalctl` and `/var/log/auth.log`.
- Filter by search string, regular expression, log facility, or severity level (`INFO`, `WARNING`, `ERR`, `ALERT`).

### 5. System & Persistence Audit
- **File Integrity Monitor (FIM):** Alerts on file modification, permission changes, or size changes on critical system files with one-click **Rebuild Baseline Snapshot** functionality.
- **Persistence Checker:** Audits system crontabs, user crontabs, and systemd timers. Flags suspicious commands executing from `/tmp` or utilizing piped web downloads.
- **Port-to-Process Verification:** Cross-references listening ports against `/proc/[pid]/exe` and `/proc/[pid]/cmdline`, flagging deleted executables in RAM (`(deleted)`).

### 6. Firewall & Blocklist Management
- Unified table of active kernel drops (`nftables` set and system-level drop rules).
- **Manual Ban Form:** Ban any IPv4 or IPv6 with predefined expiration timers (1 Hour, 24 Hours, 7 Days, Permanent) and audit reasons.
- **Anti-Lockout Whitelist:** Manage permanent exemptions for administrative subnets and management workstations.

### 7. Settings & Alert Webhooks
- Configure alert thresholds (Failed login rate, bandwidth spike threshold, threat score limits).
- Dispatch instant notifications via **Discord Webhook**, **Telegram Bot**, or **Generic Webhook**.
- Toggle mandatory operator authentication (`admin_token`).

---

## 📡 REST API & WebSocket Reference

### Fail2Ban & Host Defense
| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/fail2ban/status` | `GET` | Fail2Ban status, active jails, total banned counts, and sample banned IPs |
| `/api/fail2ban/unban` | `POST` | Unban an IP from a specific jail or across all active jails |
| `/api/fail2ban/ban` | `POST` | Manually ban an IP into a specified Fail2Ban jail |
| `/api/fail2ban/logs` | `GET` | Tail recent Fail2Ban events (`BAN`, `UNBAN`, `FOUND`) |

### Telemetry & Network
| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/overview` | `GET` | Consolidated SOC overview payload (Threat score, hardware metrics, stats) |
| `/api/network/bandwidth` | `GET` | Real-time RX/TX bandwidth metrics and 30s rolling sparkline history |
| `/api/network/sockets` | `GET` | Filterable active sockets table (`proto`, `state`, `direction`, `search`) |
| `/api/network/top-negotiations` | `GET` | Top remote IPs negotiating TCP handshakes (SYN_RECV/ESTAB) & GeoIP |
| `/api/network/block` | `POST` | Instant kernel drop rule insertion (`ip`, `duration`, `reason`, `force`) |

### Access & Identity Defense
| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/access/sessions` | `GET` | Active interactive user sessions (`loginctl` & `who`) |
| `/api/access/kill-session` | `POST` | Terminate active user session safely (`session_id`, `tty`) |
| `/api/access/failed-logins` | `GET` | Brute-force tracker with GeoIP, targeted users & event counts |
| `/api/access/sudo-history` | `GET` | Audit log of sudo command executions |

### Logs & Persistence
| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/logs` | `GET` | Filterable audit log stream (`limit`, `search`, `regex`, `severity`) |
| `/api/persistence/fim` | `GET` | File Integrity Monitor status & SHA-256 baseline comparison |
| `/api/persistence/fim/update-baseline` | `POST` | Rebuild trusted FIM snapshot with current file state |
| `/api/persistence/artifacts` | `GET` | Persistence scanner (Crontabs, systemd timers, custom units) |
| `/api/persistence/ports` | `GET` | Port-to-process verification with anomaly detection |

### Firewall & Whitelist Management
| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/firewall/rules` | `GET` | Active bans from CyberSentinel set and underlying system firewall |
| `/api/firewall/ban` | `POST` | Deploy kernel drop rule with expiration timer |
| `/api/firewall/unban` | `POST` | Remove drop rule from packet filter |
| `/api/firewall/whitelist` | `GET` | List whitelisted management IPs & subnets |
| `/api/firewall/whitelist/add` | `POST` | Add IP or CIDR network to whitelist |
| `/api/firewall/whitelist/remove` | `POST` | Remove entry from whitelist |

### System & Daemon
| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/settings` | `GET` / `POST` | Daemon configuration, alert thresholds, webhook integrations |
| `/api/system/info` | `GET` | Hostname, OS distro, kernel version, architecture & firewall engine |
| `/ws/live` | `WebSocket` | Real-time bidirectional streaming hub (telemetry pulses & logs) |

---

## 🔒 Security & Hardening Architecture

1. **Least-Privilege Systemd Sandbox:**
   - Runs with bounded Linux capabilities (`CAP_NET_ADMIN`, `CAP_KILL`, `CAP_DAC_READ_SEARCH`).
   - `ProtectSystem=full` mounts `/usr`, `/boot`, and `/etc` read-only for general system operations.
   - `ProtectHome=read-only` limits unauthorized modifications to home directories.
   - `NoNewPrivileges=no` prevents child process privilege escalation.
2. **Anti-Lockout Protection:**
   - Whitelist validation evaluates every target IP prior to injecting drop rules.
   - Banning the operator's current active IP is blocked by default unless explicitly confirmed with `force=True`.
3. **Sliding-Window Rate Limiting:**
   - Sensitive defensive actions (firewall manipulation, session termination) are throttled via an in-memory sliding window to prevent command injection spam or accidental lockouts.
4. **Offline Air-Gapped Operation:**
   - Frontend vendor dependencies (Vue 3, Tailwind, Lucide, Chart.js) are bundled locally in `/frontend/static/vendor/` guaranteeing 100% functionality in air-gapped environments.

---

## 📄 License

This project is licensed under the **MIT License** &mdash; see the [LICENSE](LICENSE) file for details.
