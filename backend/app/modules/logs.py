"""Security Logs & Audit subsystem: log ingestion, regex searching, and categorization."""
import re
import logging
import subprocess
from typing import Dict, Any, List, Optional

logger = logging.getLogger("cybersentinel.logs")


def categorize_log_line(line: str) -> Dict[str, Any]:
    """Classifies a log line into severity, facility, and parsed metadata."""
    severity = "info"
    facility = "system"
    clean_line = line.strip()

    line_lower = clean_line.lower()

    if "sshd" in line_lower:
        facility = "sshd"
        if "failed password" in line_lower or "invalid user" in line_lower:
            severity = "critical" if "root" in line_lower else "warning"
        elif "[preauth]" in line_lower:
            severity = "warning"
        elif "accepted" in line_lower:
            severity = "info"
    elif "sudo:" in line_lower:
        facility = "sudo"
        if "authentication failure" in line_lower or "incorrect password" in line_lower:
            severity = "critical"
        else:
            severity = "info"
    elif "kernel:" in line_lower or "drop" in line_lower or "reject" in line_lower:
        facility = "firewall"
        severity = "warning"

    return {
        "raw": clean_line,
        "facility": facility,
        "severity": severity,
    }


def query_logs(
    limit: int = 100,
    search: Optional[str] = None,
    regex_pattern: Optional[str] = None,
    facility: Optional[str] = None,
    severity: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Queries security audit logs from /var/log/auth.log or journalctl.
    Applies search, regex, facility, and severity filters.
    """
    raw_lines: List[str] = []

    # Try reading /var/log/auth.log first
    log_files = ["/var/log/auth.log", "/var/log/secure"]
    for lf in log_files:
        try:
            with open(lf, "r", encoding="utf-8", errors="ignore") as f:
                raw_lines = f.readlines()[-2000:]
                break
        except Exception:
            continue

    # Fallback to journalctl if file is not accessible
    if not raw_lines:
        try:
            res = subprocess.run(
                ["journalctl", "-n", "1000", "--no-pager"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if res.returncode == 0:
                raw_lines = res.stdout.splitlines()
        except Exception as e:
            logger.error(f"Error executing journalctl: {e}")

    # Compile regex if provided
    compiled_regex = None
    if regex_pattern:
        try:
            compiled_regex = re.compile(regex_pattern, re.IGNORECASE)
        except re.error as e:
            return {"error": f"Invalid regex pattern: {e}", "logs": [], "total": 0}

    filtered_logs: List[Dict[str, Any]] = []

    # Process in reverse (most recent first)
    for line in reversed(raw_lines):
        line = line.strip()
        if not line:
            continue

        item = categorize_log_line(line)

        # Apply facility filter
        if facility and facility.lower() != "all" and item["facility"] != facility.lower():
            continue

        # Apply severity filter
        if severity and severity.lower() != "all" and item["severity"] != severity.lower():
            continue

        # Apply text search
        if search and search.lower() not in line.lower():
            continue

        # Apply regex filter
        if compiled_regex and not compiled_regex.search(line):
            continue

        filtered_logs.append(item)
        if len(filtered_logs) >= limit:
            break

    return {
        "logs": filtered_logs,
        "total": len(filtered_logs),
        "query": {
            "limit": limit,
            "search": search,
            "regex": regex_pattern,
            "facility": facility,
            "severity": severity,
        },
    }
