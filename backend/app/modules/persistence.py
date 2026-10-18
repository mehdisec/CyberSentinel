"""Threat Detection & Persistence Auditing: FIM, Cron/Systemd persistence, and Port-to-Process verification."""
import os
import glob
import json
import time
import hashlib
import stat
import pwd
import grp
import subprocess
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from backend.app.core.config import settings

logger = logging.getLogger("cybersentinel.persistence")


def compute_file_hash(filepath: str) -> Optional[Dict[str, Any]]:
    """Computes SHA-256, permissions, ownership, and mtime for a given file."""
    p = Path(filepath)
    if not p.exists() or not p.is_file():
        return None

    try:
        st = p.stat()
        sha256 = hashlib.sha256()
        with open(p, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)

        # Resolve owner and group names
        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            owner = str(st.st_uid)

        try:
            group = grp.getgrgid(st.st_gid).gr_name
        except KeyError:
            group = str(st.st_gid)

        return {
            "path": filepath,
            "sha256": sha256.hexdigest(),
            "size": st.st_size,
            "mode": oct(stat.S_IMODE(st.st_mode)),
            "owner": owner,
            "group": group,
            "mtime": st.st_mtime,
            "mtime_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
        }
    except Exception as e:
        logger.warning(f"Error computing hash for {filepath}: {e}")
        return None


class FileIntegrityMonitor:
    """
    Periodic and on-demand SHA-256 baseline checking on critical paths.
    Detects unauthorized file modifications, permission escalations, or tampering.
    """

    def __init__(self):
        self.baseline_file = settings.fim_baseline_file
        self.monitored_paths = settings.fim_paths
        self.baseline: Dict[str, Any] = self._load_baseline()
        if not self.baseline:
            self.create_baseline("Initial auto-generated baseline on startup")

    def _load_baseline(self) -> Dict[str, Any]:
        if self.baseline_file.exists():
            try:
                with open(self.baseline_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed loading FIM baseline: {e}")
        return {}

    def create_baseline(self, reason: str = "Admin baseline update") -> Dict[str, Any]:
        """Creates or updates the trusted baseline snapshot of all monitored files."""
        records: Dict[str, Any] = {}
        for path_str in self.monitored_paths:
            # Handle glob patterns if any
            matched_paths = glob.glob(path_str) if any(c in path_str for c in "*?[]") else [path_str]
            for p in matched_paths:
                info = compute_file_hash(p)
                if info:
                    records[p] = info

        self.baseline = {
            "created_at": time.time(),
            "created_at_str": time.strftime("%Y-%m-%d %H:%M:%S"),
            "reason": reason,
            "files": records,
        }

        try:
            self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.baseline_file, "w", encoding="utf-8") as f:
                json.dump(self.baseline, f, indent=2)
            logger.info(f"FIM baseline saved with {len(records)} files to {self.baseline_file}")
        except Exception as e:
            logger.error(f"Failed saving FIM baseline: {e}")

        return self.baseline

    def verify_integrity(self) -> Dict[str, Any]:
        """Compares current filesystem state against trusted baseline."""
        results: List[Dict[str, Any]] = []
        anomalies_count = 0
        baseline_files = self.baseline.get("files", {})

        all_target_paths = set(baseline_files.keys())
        for path_str in self.monitored_paths:
            for p in glob.glob(path_str) if any(c in path_str for c in "*?[]") else [path_str]:
                all_target_paths.add(p)

        for p in sorted(all_target_paths):
            current = compute_file_hash(p)
            base = baseline_files.get(p)

            if not current and base:
                status_str = "MISSING"
                severity = "critical"
                anomalies_count += 1
                diff = "File existed in baseline but is now deleted!"
            elif current and not base:
                status_str = "NEW_UNTRACKED"
                severity = "warning"
                anomalies_count += 1
                diff = "New critical file present not in baseline snapshot"
            elif current and base:
                if current["sha256"] != base["sha256"]:
                    status_str = "MODIFIED"
                    severity = "critical"
                    anomalies_count += 1
                    diff = f"SHA-256 changed: expected {base['sha256'][:10]}..., got {current['sha256'][:10]}..."
                elif current["mode"] != base["mode"]:
                    status_str = "PERM_CHANGED"
                    severity = "warning"
                    anomalies_count += 1
                    diff = f"Permissions altered: {base['mode']} -> {current['mode']}"
                elif current["owner"] != base["owner"] or current["group"] != base["group"]:
                    status_str = "OWNER_CHANGED"
                    severity = "warning"
                    anomalies_count += 1
                    diff = f"Owner altered: {base['owner']}:{base['group']} -> {current['owner']}:{current['group']}"
                else:
                    status_str = "VERIFIED_OK"
                    severity = "ok"
                    diff = "Matches trusted baseline"
            else:
                continue

            results.append({
                "path": p,
                "status": status_str,
                "severity": severity,
                "diff": diff,
                "current": current,
                "baseline": base,
            })

        return {
            "baseline_created_at": self.baseline.get("created_at_str", "Never"),
            "baseline_reason": self.baseline.get("reason", "-"),
            "total_monitored": len(results),
            "anomalies_count": anomalies_count,
            "has_threat": anomalies_count > 0,
            "files": results,
        }


fim_monitor = FileIntegrityMonitor()


def get_persistence_artifacts() -> Dict[str, Any]:
    """
    Audits persistence mechanisms: Crontabs (/etc/cron*, user crontabs),
    systemd timers, and custom service units in /etc/systemd/system.
    """
    cron_entries: List[Dict[str, Any]] = []

    # 1. System /etc/crontab
    if os.path.exists("/etc/crontab"):
        try:
            with open("/etc/crontab", "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        cron_entries.append({
                            "source": "/etc/crontab",
                            "user": "system",
                            "command": line,
                            "is_suspicious": "curl" in line or "wget" in line or "/tmp" in line,
                        })
        except Exception:
            pass

    # 2. /etc/cron.d/
    if os.path.exists("/etc/cron.d"):
        for fname in os.listdir("/etc/cron.d"):
            fpath = os.path.join("/etc/cron.d", fname)
            if os.path.isfile(fpath) and not fname.startswith("."):
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                cron_entries.append({
                                    "source": f"/etc/cron.d/{fname}",
                                    "user": "cron.d",
                                    "command": line,
                                    "is_suspicious": "curl" in line or "wget" in line or "/tmp" in line,
                                })
                except Exception:
                    pass

    # 3. User crontabs in /var/spool/cron/crontabs/
    user_cron_dir = "/var/spool/cron/crontabs"
    if os.path.exists(user_cron_dir):
        try:
            for user in os.listdir(user_cron_dir):
                user_fpath = os.path.join(user_cron_dir, user)
                if os.path.isfile(user_fpath):
                    with open(user_fpath, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                cron_entries.append({
                                    "source": f"crontab:{user}",
                                    "user": user,
                                    "command": line,
                                    "is_suspicious": "curl" in line or "wget" in line or "/tmp" in line,
                                })
        except Exception:
            pass

    # 4. Systemd Timers
    systemd_timers: List[Dict[str, Any]] = []
    try:
        res = subprocess.run(["systemctl", "list-timers", "--all", "--no-pager"], capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            lines = res.stdout.strip().splitlines()
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 6 and ".timer" in line:
                    timer_unit = [p for p in parts if p.endswith(".timer")]
                    service_unit = [p for p in parts if p.endswith(".service")]
                    if timer_unit and service_unit:
                        systemd_timers.append({
                            "timer": timer_unit[0],
                            "activates": service_unit[0],
                            "raw": line[:100],
                        })
    except Exception as e:
        logger.warning(f"Error listing systemd timers: {e}")

    # 5. Non-standard / Custom Services in /etc/systemd/system/
    custom_services: List[Dict[str, Any]] = []
    etc_systemd = "/etc/systemd/system"
    if os.path.exists(etc_systemd):
        for fname in os.listdir(etc_systemd):
            if fname.endswith(".service") and not os.path.islink(os.path.join(etc_systemd, fname)):
                fpath = os.path.join(etc_systemd, fname)
                exec_start = "-"
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if line.strip().startswith("ExecStart="):
                                exec_start = line.strip().split("=", 1)[1]
                                break
                except Exception:
                    pass
                is_suspicious = any(x in exec_start for x in ["/tmp", "/dev/shm", "curl", "wget", "bash -i"])
                custom_services.append({
                    "name": fname,
                    "path": fpath,
                    "exec_start": exec_start,
                    "is_suspicious": is_suspicious,
                })

    return {
        "cron_entries": cron_entries,
        "systemd_timers": systemd_timers,
        "custom_services": custom_services,
        "total_cron": len(cron_entries),
        "total_timers": len(systemd_timers),
        "total_custom_services": len(custom_services),
    }


def verify_listening_ports() -> List[Dict[str, Any]]:
    """
    Cross-references listening ports with process binaries and command lines.
    Flags anomalies like deleted executables, binaries running from /tmp, or hidden binaries.
    """
    listening: List[Dict[str, Any]] = []

    # ss -tulpn
    try:
        res = subprocess.run(["ss", "-H", "-t", "-u", "-l", "-p", "-n"], capture_output=True, text=True, timeout=3)
        raw_output = res.stdout
    except Exception as e:
        logger.error(f"Error running ss -tulpn: {e}")
        return listening

    import re
    users_regex = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')

    for line in raw_output.strip().splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue

        proto = parts[0].lower()
        local_addr = parts[4]

        # Extract address & port
        r_idx = local_addr.rfind(":")
        if r_idx == -1:
            continue
        ip = local_addr[:r_idx].strip("[]%")
        port = local_addr[r_idx + 1 :]

        # Extract PID & process name
        pid = None
        proc_name = "-"
        remainder = " ".join(parts[5:]) if len(parts) > 5 else ""
        match = users_regex.search(remainder)
        if match:
            proc_name = match.group(1)
            pid = int(match.group(2))

        exe_path = "-"
        cmdline = "-"
        is_deleted = False
        is_suspicious_dir = False
        is_hidden_name = False
        user_owner = "-"
        risk_level = "CLEAN"
        anomaly_reasons = []

        if pid:
            # 1. Inspect /proc/[pid]/exe
            try:
                real_exe = os.readlink(f"/proc/{pid}/exe")
                exe_path = real_exe
                if "(deleted)" in real_exe:
                    is_deleted = True
                    anomaly_reasons.append("Binary marked (deleted) on disk - active memory execution")
                for susp_dir in ["/tmp", "/var/tmp", "/dev/shm", "/run/user"]:
                    if real_exe.startswith(susp_dir):
                        is_suspicious_dir = True
                        anomaly_reasons.append(f"Executable running from suspicious directory '{susp_dir}'")
                fname = os.path.basename(real_exe.replace(" (deleted)", ""))
                if fname.startswith(".") or fname in ["...", "kworker", "syslogd"]:
                    if fname != proc_name:
                        is_hidden_name = True
                        anomaly_reasons.append(f"Suspicious masqueraded/hidden process name '{fname}'")
            except (FileNotFoundError, PermissionError):
                exe_path = "[Permission Denied / Kernel]"

            # 2. Inspect /proc/[pid]/cmdline
            try:
                with open(f"/proc/{pid}/cmdline", "r", encoding="utf-8", errors="ignore") as f:
                    cmdline = f.read().replace("\x00", " ").strip()
            except Exception:
                pass

            # 3. Inspect process owner uid
            try:
                st = os.stat(f"/proc/{pid}")
                user_owner = pwd.getpwuid(st.st_uid).pw_name
            except Exception:
                pass

        if is_deleted or is_suspicious_dir:
            risk_level = "CRITICAL"
        elif is_hidden_name or (user_owner == "root" and ip in ("0.0.0.0", "*", "::") and int(port) > 10000 and "python" in proc_name):
            risk_level = "SUSPICIOUS"

        listening.append({
            "proto": proto,
            "ip": ip,
            "port": port,
            "pid": pid,
            "process_name": proc_name,
            "user": user_owner,
            "exe_path": exe_path,
            "cmdline": cmdline[:120] if cmdline else "-",
            "is_deleted": is_deleted,
            "is_suspicious_dir": is_suspicious_dir,
            "risk_level": risk_level,
            "anomalies": anomaly_reasons,
        })

    return listening
