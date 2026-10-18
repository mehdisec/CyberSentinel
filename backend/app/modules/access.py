"""Identity & Access Management: active sessions, failed login tracker, and sudo execution audit."""
import re
import time
import subprocess
import logging
import ipaddress
from typing import Dict, Any, List, Optional
import requests
from backend.app.core.security import is_ip_whitelisted

logger = logging.getLogger("cybersentinel.access")

# GeoIP in-memory cache: ip -> {country, country_code, city, isp}
_GEO_CACHE: Dict[str, Dict[str, str]] = {}

# Regular expressions for SSH security events
RE_FAILED_PWD = re.compile(
    r"(?P<ts>\S+)\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) ssh2"
)
RE_INVALID_USER = re.compile(
    r"(?P<ts>\S+)\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+Invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
RE_PREAUTH_CLOSED = re.compile(
    r"(?P<ts>\S+)\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+Connection closed by (authenticating user (?P<user>\S+) )?(?P<ip>\S+) port (?P<port>\d+)"
)
RE_PREAUTH_DISCONN = re.compile(
    r"(?P<ts>\S+)\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+Disconnected from authenticating user (?P<user>\S+) (?P<ip>\S+) port (?P<port>\d+) \[preauth\]"
)
RE_SUDO_EXEC = re.compile(
    r"(?P<ts>\S+)\s+(?P<host>\S+)\s+sudo:\s+(?P<user>\S+)\s+:\s+TTY=(?P<tty>\S+)\s+;\s+PWD=(?P<pwd>\S+)\s+;\s+USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<command>.*)"
)


def resolve_geo_ip(ip_str: str) -> Dict[str, str]:
    """
    Resolves country, country code, city, and ISP with memory caching.
    Bogon / private IPs are handled locally without network calls.
    """
    if not ip_str or ip_str in ("-", "127.0.0.1", "::1", "localhost"):
        return {"country": "Localhost", "country_code": "LOC", "city": "Internal", "isp": "Loopback"}

    if ip_str in _GEO_CACHE:
        return _GEO_CACHE[ip_str]

    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            result = {"country": "Private Network", "country_code": "LAN", "city": "Internal", "isp": "RFC1918"}
            _GEO_CACHE[ip_str] = result
            return result
    except ValueError:
        return {"country": "Invalid", "country_code": "ERR", "city": "-", "isp": "-"}

    # Attempt lookup via free IP-API with short timeout
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip_str}?fields=status,country,countryCode,city,isp,org",
            timeout=1.5,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                result = {
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "UN"),
                    "city": data.get("city", "-"),
                    "isp": data.get("isp", data.get("org", "Unknown")),
                }
                _GEO_CACHE[ip_str] = result
                return result
    except Exception:
        pass

    fallback = {"country": "Unknown", "country_code": "UN", "city": "-", "isp": "Unknown ISP"}
    _GEO_CACHE[ip_str] = fallback
    return fallback


def get_active_sessions() -> List[Dict[str, Any]]:
    """
    Monitors active interactive user sessions using loginctl and 'who -u' / 'w'.
    Provides session IDs and terminal identifiers required for safe session termination.
    """
    sessions: List[Dict[str, Any]] = []

    # Map TTY to loginctl session ID
    tty_to_session_id: Dict[str, str] = {}
    try:
        res = subprocess.run(
            ["loginctl", "list-sessions", "--no-legend"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5:
                    sess_id = parts[0]
                    tty = parts[4]
                    if tty != "-":
                        tty_to_session_id[tty] = sess_id
    except Exception as e:
        logger.warning(f"loginctl list-sessions failed: {e}")

    # Inspect who / w
    try:
        res = subprocess.run(["who", "-u"], capture_output=True, text=True, timeout=2)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5:
                    user = parts[0]
                    tty = parts[1]
                    login_time = f"{parts[2]} {parts[3]}"
                    idle = parts[4]
                    pid = parts[5] if len(parts) > 5 and parts[5].isdigit() else "-"
                    remote_host = parts[-1].strip("()") if "(" in line else "local"

                    sess_id = tty_to_session_id.get(tty, tty)

                    # Inspect what command the shell is running
                    curr_cmd = "bash/sh"
                    if pid.isdigit():
                        try:
                            with open(f"/proc/{pid}/cmdline", "r", encoding="utf-8", errors="ignore") as f:
                                cmdline = f.read().replace("\x00", " ").strip()
                                if cmdline:
                                    curr_cmd = cmdline[:60]
                        except Exception:
                            pass

                    geo = resolve_geo_ip(remote_host)

                    sessions.append({
                        "session_id": sess_id,
                        "user": user,
                        "tty": tty,
                        "remote_ip": remote_host,
                        "geo": geo,
                        "login_time": login_time,
                        "idle": idle,
                        "pid": pid,
                        "command": curr_cmd,
                        "is_root": user == "root",
                    })
    except Exception as e:
        logger.error(f"Failed parsing active sessions: {e}")

    return sessions


def kill_session(session_id: str, tty: Optional[str] = None) -> Dict[str, Any]:
    """
    Safely terminates an active login session via loginctl or pkill.
    """
    session_id = session_id.strip()
    terminated = False
    methods_tried = []

    # Method 1: loginctl terminate-session
    if session_id.isdigit():
        try:
            res = subprocess.run(["loginctl", "terminate-session", session_id], capture_output=True, text=True, timeout=3)
            methods_tried.append("loginctl")
            if res.returncode == 0:
                terminated = True
        except Exception as e:
            logger.warning(f"loginctl terminate-session failed: {e}")

    # Method 2: pkill -9 -t <tty>
    target_tty = tty or (session_id if "/" in session_id else None)
    if not terminated and target_tty:
        clean_tty = target_tty.replace("/dev/", "")
        try:
            res = subprocess.run(["pkill", "-9", "-t", clean_tty], capture_output=True, text=True, timeout=3)
            methods_tried.append(f"pkill -t {clean_tty}")
            if res.returncode == 0:
                terminated = True
        except Exception as e:
            logger.warning(f"pkill failed: {e}")

    return {
        "success": terminated,
        "session_id": session_id,
        "tty": target_tty,
        "methods_tried": methods_tried,
    }


def get_failed_logins(max_entries: int = 100) -> Dict[str, Any]:
    """
    Parses /var/log/auth.log and journalctl for failed SSH authentication attempts,
    brute-force probes, and preauth disconnects. Aggregates per remote IP.
    """
    attackers: Dict[str, Dict[str, Any]] = {}
    total_events = 0

    log_files = ["/var/log/auth.log", "/var/log/secure"]
    lines: List[str] = []

    for lf in log_files:
        try:
            with open(lf, "r", encoding="utf-8", errors="ignore") as f:
                # Read last 3000 lines
                chunk = f.readlines()[-3000:]
                lines.extend(chunk)
                break  # stop at first available
        except FileNotFoundError:
            continue
        except Exception as e:
            logger.warning(f"Could not read {lf}: {e}")

    # If no auth file found, fallback to journalctl
    if not lines:
        try:
            res = subprocess.run(
                ["journalctl", "-u", "ssh", "-u", "sshd", "-n", "1000", "--no-pager"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if res.returncode == 0:
                lines = res.stdout.splitlines()
        except Exception:
            pass

    for line in lines:
        match_failed = RE_FAILED_PWD.search(line)
        match_invalid = RE_INVALID_USER.search(line)
        match_preauth_closed = RE_PREAUTH_CLOSED.search(line)
        match_preauth_disconn = RE_PREAUTH_DISCONN.search(line)

        ip = None
        user = "unknown"
        event_type = "FAILED_LOGIN"
        ts = ""

        if match_failed:
            d = match_failed.groupdict()
            ip = d["ip"]
            user = d.get("user") or "unknown"
            event_type = "BRUTE_FORCE_PWD"
            ts = d["ts"]
        elif match_invalid:
            d = match_invalid.groupdict()
            ip = d["ip"]
            user = d.get("user") or "unknown"
            event_type = "INVALID_USER"
            ts = d["ts"]
        elif match_preauth_closed:
            d = match_preauth_closed.groupdict()
            ip = d["ip"]
            user = d.get("user") or "preauth"
            event_type = "PREAUTH_DROP"
            ts = d["ts"]
        elif match_preauth_disconn:
            d = match_preauth_disconn.groupdict()
            ip = d["ip"]
            user = d.get("user") or "preauth"
            event_type = "PREAUTH_DISCONNECT"
            ts = d["ts"]

        if ip:
            total_events += 1
            if ip not in attackers:
                attackers[ip] = {
                    "ip": ip,
                    "count": 0,
                    "attacked_users": set(),
                    "first_seen": ts,
                    "last_seen": ts,
                    "primary_event": event_type,
                    "is_whitelisted": is_ip_whitelisted(ip),
                }

            attackers[ip]["count"] += 1
            if user and user not in ("unknown", "preauth", None):
                attackers[ip]["attacked_users"].add(user)
            attackers[ip]["last_seen"] = ts

    # Sort attackers by attempt count descending
    sorted_attackers = sorted(attackers.values(), key=lambda x: x["count"], reverse=True)[:max_entries]

    # Enrich top attackers with GeoIP and list conversion
    results = []
    for item in sorted_attackers:
        geo = resolve_geo_ip(item["ip"])
        users_list = sorted(list(item["attacked_users"]))
        results.append({
            "ip": item["ip"],
            "count": item["count"],
            "attacked_users": users_list[:10],
            "total_users_targeted": len(users_list),
            "first_seen": item["first_seen"],
            "last_seen": item["last_seen"],
            "event_type": item["primary_event"],
            "geo": geo,
            "is_whitelisted": item["is_whitelisted"],
        })

    return {
        "total_failed_events": total_events,
        "unique_attackers": len(attackers),
        "attackers": results,
    }


def get_sudo_history(max_entries: int = 100) -> List[Dict[str, Any]]:
    """
    Parses security logs for sudo command executions.
    Extracts timestamp, calling user, target user, TTY, working directory, and command.
    """
    sudo_logs: List[Dict[str, Any]] = []
    log_files = ["/var/log/auth.log", "/var/log/secure"]
    lines: List[str] = []

    for lf in log_files:
        try:
            with open(lf, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[-4000:]
                break
        except Exception:
            continue

    if not lines:
        try:
            res = subprocess.run(
                ["journalctl", "_COMM=sudo", "-n", "500", "--no-pager"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if res.returncode == 0:
                lines = res.stdout.splitlines()
        except Exception:
            pass

    for line in reversed(lines):
        match = RE_SUDO_EXEC.search(line)
        if match:
            d = match.groupdict()
            cmd = d["command"].strip()
            # Security classification
            is_sensitive = any(
                sensitive_cmd in cmd
                for sensitive_cmd in ["passwd", "shadow", "chmod", "chown", "iptables", "nft", "useradd", "visudo", "rm -rf"]
            )
            sudo_logs.append({
                "timestamp": d["ts"],
                "user": d["user"],
                "target_user": d["target_user"],
                "tty": d["tty"],
                "pwd": d["pwd"],
                "command": cmd,
                "is_sensitive": is_sensitive,
            })
            if len(sudo_logs) >= max_entries:
                break

    return sudo_logs
