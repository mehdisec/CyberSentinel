"""Fail2Ban subsystem: jail monitoring, banned IP inspection, unban/ban actions, and log parsing."""
import os
import re
import shutil
import logging
import subprocess
from typing import Dict, Any, List, Optional
from backend.app.modules.access import resolve_geo_ip

logger = logging.getLogger("cybersentinel.fail2ban")

# Regex to parse /var/log/fail2ban.log
# Example: 2026-10-17 21:12:12,731 fail2ban.filter [1698520]: INFO [sshd] Found 70.34.202.108 - 2026-10-17 21:12:12
# Example: 2026-10-17 21:00:00,123 fail2ban.actions [1698520]: NOTICE [sshd-aggressive] Ban 198.51.100.4
RE_F2B_LOG = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d+)\s+fail2ban\.(?P<module>\S+)\s+\[(?P<pid>\d+)\]:\s+(?P<level>[A-Z]+)\s+\[(?P<jail>[^\]]+)\]\s+(?P<action>Ban|Unban|Found)\s+(?P<ip>\S+)"
)


def is_fail2ban_available() -> bool:
    """Checks if fail2ban-client binary exists on the system."""
    return shutil.which("fail2ban-client") is not None


def get_fail2ban_status() -> Dict[str, Any]:
    """
    Queries fail2ban-client for server status and iterates through all active jails.
    Gathers currently banned, total banned, currently failed, total failed, and banned IPs.
    """
    if not is_fail2ban_available():
        return {
            "installed": False,
            "running": False,
            "total_jails": 0,
            "jails": [],
            "total_currently_banned": 0,
            "total_historical_bans": 0,
            "total_failed_attempts": 0,
        }

    # 1. Query server status
    try:
        res = subprocess.run(["fail2ban-client", "status"], capture_output=True, text=True, timeout=3)
        if res.returncode != 0:
            return {
                "installed": True,
                "running": False,
                "error": res.stderr.strip() or "Fail2Ban service not running",
                "total_jails": 0,
                "jails": [],
                "total_currently_banned": 0,
                "total_historical_bans": 0,
                "total_failed_attempts": 0,
            }
    except Exception as e:
        logger.error(f"Error executing fail2ban-client status: {e}")
        return {"installed": True, "running": False, "error": str(e), "jails": []}

    jails_list = []
    for line in res.stdout.splitlines():
        if "Jail list:" in line:
            raw = line.split("Jail list:")[1].strip()
            jails_list = [j.strip() for j in raw.split(",") if j.strip()]

    jails_data: List[Dict[str, Any]] = []
    total_currently_banned = 0
    total_historical_bans = 0
    total_failed = 0
    all_banned_ips_set = set()

    # 2. Query each jail
    for j_name in jails_list:
        try:
            jr = subprocess.run(["fail2ban-client", "status", j_name], capture_output=True, text=True, timeout=3)
            cur_failed = 0
            tot_failed = 0
            cur_banned = 0
            tot_banned = 0
            banned_ips: List[str] = []

            for l in jr.stdout.splitlines():
                if "Currently failed:" in l:
                    cur_failed = int(l.split("Currently failed:")[1].strip())
                elif "Total failed:" in l:
                    tot_failed = int(l.split("Total failed:")[1].strip())
                elif "Currently banned:" in l:
                    cur_banned = int(l.split("Currently banned:")[1].strip())
                elif "Total banned:" in l:
                    tot_banned = int(l.split("Total banned:")[1].strip())
                elif "Banned IP list:" in l:
                    raw_ips = l.split("Banned IP list:")[1].strip()
                    banned_ips = [ip.strip() for ip in raw_ips.split() if ip.strip()]

            total_currently_banned += cur_banned
            total_historical_bans += tot_banned
            total_failed += tot_failed
            for ip in banned_ips:
                all_banned_ips_set.add(ip)

            jails_data.append({
                "name": j_name,
                "currently_failed": cur_failed,
                "total_failed": tot_failed,
                "currently_banned": cur_banned,
                "total_banned": tot_banned,
                "banned_ips_count": len(banned_ips),
                "banned_ips": banned_ips[:200],  # cap list for payload efficiency
            })
        except Exception as e:
            logger.warning(f"Error getting status for jail {j_name}: {e}")

    # Top sample of banned IPs enriched with GeoIP
    enriched_banned_samples = []
    for ip in list(all_banned_ips_set)[:30]:
        geo = resolve_geo_ip(ip)
        # Find which jails have this IP
        in_jails = [jd["name"] for jd in jails_data if ip in jd["banned_ips"]]
        enriched_banned_samples.append({
            "ip": ip,
            "jails": in_jails,
            "geo": geo,
        })

    return {
        "installed": True,
        "running": True,
        "total_jails": len(jails_data),
        "total_currently_banned": total_currently_banned,
        "total_historical_bans": total_historical_bans,
        "total_failed_attempts": total_failed,
        "unique_banned_ips_count": len(all_banned_ips_set),
        "jails": jails_data,
        "sample_banned_ips": enriched_banned_samples,
    }


def unban_ip_fail2ban(ip_str: str, jail: Optional[str] = None) -> Dict[str, Any]:
    """
    Unbans an IP address from Fail2Ban.
    If jail is specified, unbans from that jail.
    Otherwise, unbans from all active jails where the IP is found.
    """
    if not is_fail2ban_available():
        return {"success": False, "error": "Fail2Ban is not installed"}

    ip_str = ip_str.strip()
    status_info = get_fail2ban_status()
    jails = [j["name"] for j in status_info.get("jails", [])]

    target_jails = [jail] if jail and jail in jails else jails
    unbanned_from = []
    errors = []

    for j in target_jails:
        cmd = ["fail2ban-client", "set", j, "unbanip", ip_str]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0 and ip_str in res.stdout:
            unbanned_from.append(j)
        elif res.returncode != 0 and "not banned" not in res.stderr.lower():
            errors.append(f"{j}: {res.stderr.strip()}")

    # If already unbanned or not found in target jails
    if not unbanned_from and not errors:
        return {"success": True, "message": f"{ip_str} was not active in target jails or was already unbanned", "jails": []}

    logger.info(f"Fail2ban unbanned {ip_str} from {unbanned_from}")
    return {
        "success": len(unbanned_from) > 0 or len(errors) == 0,
        "ip": ip_str,
        "unbanned_from_jails": unbanned_from,
        "errors": errors,
    }


def ban_ip_fail2ban(ip_str: str, jail: str = "sshd-aggressive") -> Dict[str, Any]:
    """Manually bans an IP address in a specified Fail2Ban jail."""
    if not is_fail2ban_available():
        return {"success": False, "error": "Fail2Ban is not installed"}

    ip_str = ip_str.strip()
    cmd = ["fail2ban-client", "set", jail, "banip", ip_str]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0:
        logger.info(f"Fail2ban banned {ip_str} in jail {jail}")
        return {"success": True, "ip": ip_str, "jail": jail}
    return {"success": False, "error": res.stderr.strip() or "Failed to ban in fail2ban"}


def get_fail2ban_logs(limit: int = 100) -> List[Dict[str, Any]]:
    """Parses /var/log/fail2ban.log for recent Ban, Unban, and Found events."""
    log_file = "/var/log/fail2ban.log"
    if not os.path.exists(log_file):
        return []

    events = []
    try:
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()[-1500:]

        for line in reversed(lines):
            match = RE_F2B_LOG.search(line)
            if match:
                d = match.groupdict()
                events.append({
                    "timestamp": d["ts"],
                    "jail": d["jail"],
                    "action": d["action"].upper(),
                    "ip": d["ip"],
                    "level": d["level"],
                })
                if len(events) >= limit:
                    break
    except Exception as e:
        logger.error(f"Error parsing fail2ban log: {e}")

    return events
