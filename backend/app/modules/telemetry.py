"""System telemetry and Cybersecurity Threat Score calculation."""
import os
import time
import logging
from typing import Dict, Any, List, Tuple
from backend.app.modules.network import bandwidth_tracker
from backend.app.modules.access import get_failed_logins, get_active_sessions
from backend.app.modules.persistence import fim_monitor, verify_listening_ports

logger = logging.getLogger("cybersentinel.telemetry")

_LAST_CPU_TIMES: Tuple[int, int] = (0, 0)  # (idle_time, total_time)


def get_cpu_usage() -> Dict[str, Any]:
    """Calculates CPU usage from /proc/stat without external dependencies."""
    global _LAST_CPU_TIMES
    cores = []
    total_percent = 0.0

    if not os.path.exists("/proc/stat"):
        return {"total_percent": 0.0, "cores": []}

    try:
        with open("/proc/stat", "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Parse total cpu line
        cpu_line = lines[0].split()
        user = int(cpu_line[1])
        nice = int(cpu_line[2])
        system = int(cpu_line[3])
        idle = int(cpu_line[4])
        iowait = int(cpu_line[5]) if len(cpu_line) > 5 else 0
        irq = int(cpu_line[6]) if len(cpu_line) > 6 else 0
        softirq = int(cpu_line[7]) if len(cpu_line) > 7 else 0
        steal = int(cpu_line[8]) if len(cpu_line) > 8 else 0

        idle_time = idle + iowait
        total_time = user + nice + system + idle_time + irq + softirq + steal

        prev_idle, prev_total = _LAST_CPU_TIMES
        if prev_total > 0 and total_time > prev_total:
            diff_idle = idle_time - prev_idle
            diff_total = total_time - prev_total
            usage = 100.0 * (1.0 - (diff_idle / diff_total))
            total_percent = max(0.0, min(100.0, round(usage, 1)))

        _LAST_CPU_TIMES = (idle_time, total_time)

        # Parse per-core cpu0, cpu1...
        for line in lines[1:]:
            parts = line.split()
            if parts and parts[0].startswith("cpu") and parts[0][3:].isdigit():
                c_idle = int(parts[4])
                c_total = sum(int(x) for x in parts[1:8])
                cores.append({"core": parts[0], "total": c_total, "idle": c_idle})

    except Exception as e:
        logger.warning(f"Error parsing /proc/stat: {e}")

    return {
        "total_percent": total_percent,
        "cores_count": max(1, len(cores)),
    }


def get_memory_usage() -> Dict[str, Any]:
    """Calculates RAM and swap from /proc/meminfo."""
    mem_total = 0
    mem_free = 0
    mem_available = 0

    if os.path.exists("/proc/meminfo"):
        try:
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        k = parts[0].strip()
                        v = int(parts[1].split()[0]) * 1024  # convert kB to Bytes
                        if k == "MemTotal":
                            mem_total = v
                        elif k == "MemFree":
                            mem_free = v
                        elif k == "MemAvailable":
                            mem_available = v
        except Exception:
            pass

    used = mem_total - (mem_available or mem_free)
    percent = round((used / mem_total) * 100.0, 1) if mem_total > 0 else 0.0

    return {
        "total_bytes": mem_total,
        "used_bytes": used,
        "available_bytes": mem_available or mem_free,
        "percent": percent,
        "total_gb": round(mem_total / (1024**3), 2),
        "used_gb": round(used / (1024**3), 2),
    }


def get_disk_usage(path: str = "/") -> Dict[str, Any]:
    """Calculates disk space for root filesystem via os.statvfs."""
    try:
        st = os.statvfs(path)
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        used = total - free
        percent = round((used / total) * 100.0, 1) if total > 0 else 0.0
        return {
            "path": path,
            "total_gb": round(total / (1024**3), 2),
            "used_gb": round(used / (1024**3), 2),
            "free_gb": round(free / (1024**3), 2),
            "percent": percent,
        }
    except Exception:
        return {"path": path, "total_gb": 0, "used_gb": 0, "free_gb": 0, "percent": 0}


def get_system_uptime() -> Dict[str, Any]:
    """Reads /proc/uptime and /proc/loadavg."""
    uptime_sec = 0.0
    load_avg = [0.0, 0.0, 0.0]

    if os.path.exists("/proc/uptime"):
        try:
            with open("/proc/uptime", "r") as f:
                uptime_sec = float(f.read().split()[0])
        except Exception:
            pass

    if os.path.exists("/proc/loadavg"):
        try:
            with open("/proc/loadavg", "r") as f:
                parts = f.read().split()
                load_avg = [float(parts[0]), float(parts[1]), float(parts[2])]
        except Exception:
            pass

    days = int(uptime_sec // 86400)
    hours = int((uptime_sec % 86400) // 3600)
    minutes = int((uptime_sec % 3600) // 60)
    uptime_str = f"{days}d {hours}h {minutes}m"

    return {
        "uptime_seconds": uptime_sec,
        "uptime_str": uptime_str,
        "load_1m": load_avg[0],
        "load_5m": load_avg[1],
        "load_15m": load_avg[2],
    }


def compute_threat_score() -> Dict[str, Any]:
    """
    Computes real-time dynamic Cybersecurity Threat Score (0 to 100) based on:
    - Failed authentications / brute force volume
    - Listening ports with anomalies (deleted binaries, suspicious dirs)
    - File Integrity Monitor baseline discrepancies
    - Active root sessions from unexpected IPs
    """
    score = 0
    reasons = []

    # 1. Failed Logins & Brute Force Check
    try:
        failed_info = get_failed_logins(max_entries=20)
        recent_failures = failed_info.get("total_failed_events", 0)
        unique_attackers = failed_info.get("unique_attackers", 0)

        if recent_failures > 50:
            score += 35
            reasons.append(f"High SSH brute-force volume: {recent_failures} failures across {unique_attackers} IPs")
        elif recent_failures > 10:
            score += 20
            reasons.append(f"Moderate SSH probing: {recent_failures} attempts detected")
        elif recent_failures > 0:
            score += 10
    except Exception:
        pass

    # 2. Port-to-Process Verification
    try:
        listening_ports = verify_listening_ports()
        critical_ports = [p for p in listening_ports if p["risk_level"] == "CRITICAL"]
        suspicious_ports = [p for p in listening_ports if p["risk_level"] == "SUSPICIOUS"]

        if critical_ports:
            score += 40
            names = ", ".join(f"{p['process_name']}:{p['port']}" for p in critical_ports)
            reasons.append(f"Critical process anomalies detected on listening ports: {names}")
        elif suspicious_ports:
            score += 20
            names = ", ".join(f"{p['process_name']}:{p['port']}" for p in suspicious_ports)
            reasons.append(f"Suspicious listening process binding: {names}")
    except Exception:
        pass

    # 3. File Integrity Monitoring
    try:
        fim_result = fim_monitor.verify_integrity()
        anomalies = fim_result.get("anomalies_count", 0)
        if anomalies > 0:
            score += 30
            reasons.append(f"FIM detected {anomalies} modified or unauthorized critical files")
    except Exception:
        pass

    # 4. Active Sessions
    try:
        sessions = get_active_sessions()
        root_sessions = [s for s in sessions if s.get("is_root")]
        if len(root_sessions) > 2:
            score += 15
            reasons.append(f"Multiple concurrent root sessions active ({len(root_sessions)})")
    except Exception:
        pass

    # 5. Fail2Ban Active Threats Check
    try:
        from backend.app.modules.fail2ban import get_fail2ban_status
        f2b_stats = get_fail2ban_status()
        if f2b_stats.get("total_failed_attempts", 0) > 1000:
            score += 20
            reasons.append(f"High volume of brute force failures logged by Fail2Ban ({f2b_stats['total_failed_attempts']:,})")
        elif f2b_stats.get("total_failed_attempts", 0) > 200:
            score += 10
            reasons.append(f"Active brute force failures tracked by Fail2Ban ({f2b_stats['total_failed_attempts']:,})")
    except Exception:
        pass

    score = min(100, score)

    # Classification
    if score >= 75:
        level = "CRITICAL"
        color = "rose"
    elif score >= 50:
        level = "HIGH"
        color = "orange"
    elif score >= 25:
        level = "ELEVATED"
        color = "amber"
    else:
        level = "NORMAL"
        color = "emerald"

    return {
        "score": score,
        "level": level,
        "color": color,
        "reasons": reasons if reasons else ["No active high-risk anomalies detected. Baseline secure."],
    }


def get_full_overview() -> Dict[str, Any]:
    """Generates the consolidated SOC Dashboard overview payload."""
    cpu = get_cpu_usage()
    mem = get_memory_usage()
    disk = get_disk_usage()
    uptime = get_system_uptime()
    bw = bandwidth_tracker.get_bandwidth()
    threat = compute_threat_score()

    failed_info = get_failed_logins(max_entries=5)
    sessions = get_active_sessions()
    listening = verify_listening_ports()

    from backend.app.modules.firewall import firewall_manager
    bans = firewall_manager.list_bans()

    from backend.app.modules.network import get_top_ip_negotiations
    from backend.app.modules.fail2ban import get_fail2ban_status
    fail2ban = get_fail2ban_status()
    top_negotiations = get_top_ip_negotiations(limit=5)

    return {
        "threat": threat,
        "metrics": {
            "cpu": cpu,
            "memory": mem,
            "disk": disk,
            "uptime": uptime,
            "bandwidth": bw,
        },
        "stats": {
            "failed_logins_count": failed_info.get("total_failed_events", 0),
            "unique_attackers_count": failed_info.get("unique_attackers", 0),
            "active_sessions_count": len(sessions),
            "listening_ports_count": len(listening),
            "banned_ips_count": bans.get("total_banned", 0),
            "fail2ban_banned_count": fail2ban.get("total_currently_banned", 0),
            "fail2ban_jails_count": fail2ban.get("total_jails", 0),
            "fail2ban_running": fail2ban.get("running", False),
        },
        "fail2ban": {
            "installed": fail2ban.get("installed", False),
            "running": fail2ban.get("running", False),
            "total_currently_banned": fail2ban.get("total_currently_banned", 0),
            "total_historical_bans": fail2ban.get("total_historical_bans", 0),
            "total_failed_attempts": fail2ban.get("total_failed_attempts", 0),
            "total_jails": fail2ban.get("total_jails", 0),
            "jails": fail2ban.get("jails", []),
        },
        "quick_data": {
            "recent_sessions": sessions[:3],
            "top_attackers": failed_info.get("attackers", [])[:5],
            "top_negotiations": top_negotiations,
        },
    }
