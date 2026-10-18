"""Network monitoring subsystem: bandwidth tracking and real-time socket inspection."""
import os
import re
import time
import subprocess
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("cybersentinel.network")

# Regex to parse ss socket lines
# Example: tcp ESTAB 0 0 10.0.0.2:22 198.51.100.4:52132 users:(("sshd",pid=1234,fd=4))
SS_USERS_REGEX = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')


class BandwidthTracker:
    """
    Collects live byte counters from /proc/net/dev to calculate real-time
    inbound (RX) and outbound (TX) bandwidth rates without external dependencies.
    """

    def __init__(self, history_length: int = 30):
        self.history_length = history_length
        self.last_check_time: float = 0.0
        self.last_counters: Dict[str, Tuple[int, int]] = {}  # iface -> (rx_bytes, tx_bytes)
        self.history_rx: List[float] = []
        self.history_tx: List[float] = []
        self.timestamps: List[str] = []
        # Initial read
        self._read_proc_net_dev()

    def _read_proc_net_dev(self) -> Dict[str, Tuple[int, int]]:
        """Parses /proc/net/dev directly for rx_bytes and tx_bytes."""
        counters = {}
        if not os.path.exists("/proc/net/dev"):
            return counters

        try:
            with open("/proc/net/dev", "r", encoding="utf-8") as f:
                lines = f.readlines()

            for line in lines[2:]:
                if ":" not in line:
                    continue
                iface, data = line.split(":", 1)
                iface = iface.strip()
                fields = data.split()
                if len(fields) >= 9:
                    rx_bytes = int(fields[0])
                    tx_bytes = int(fields[8])
                    counters[iface] = (rx_bytes, tx_bytes)
        except Exception as e:
            logger.error(f"Error reading /proc/net/dev: {e}")
        return counters

    def get_bandwidth(self) -> Dict[str, Any]:
        """Calculates current RX/TX rates in KB/s and Mbps, and appends to sparkline history."""
        now = time.time()
        current_counters = self._read_proc_net_dev()
        dt = now - self.last_check_time

        rx_rate_bps = 0.0
        tx_rate_bps = 0.0
        interface_stats = {}

        if self.last_check_time > 0 and dt > 0.01:
            for iface, (rx, tx) in current_counters.items():
                if iface == "lo":
                    continue  # ignore loopback for external bandwidth
                if iface in self.last_counters:
                    prev_rx, prev_tx = self.last_counters[iface]
                    # Handle 32/64 bit counter wrap-around
                    diff_rx = rx - prev_rx if rx >= prev_rx else rx
                    diff_tx = tx - prev_tx if tx >= prev_tx else tx

                    if_rx_bps = diff_rx / dt
                    if_tx_bps = diff_tx / dt
                    rx_rate_bps += if_rx_bps
                    tx_rate_bps += if_tx_bps

                    interface_stats[iface] = {
                        "rx_rate_kbps": round((if_rx_bps * 8) / 1000, 2),
                        "tx_rate_kbps": round((if_tx_bps * 8) / 1000, 2),
                        "rx_rate_mbps": round((if_rx_bps * 8) / 1_000_000, 3),
                        "tx_rate_mbps": round((if_tx_bps * 8) / 1_000_000, 3),
                        "rx_bytes_total": rx,
                        "tx_bytes_total": tx,
                    }

        self.last_check_time = now
        self.last_counters = current_counters

        rx_kbps = round((rx_rate_bps * 8) / 1000, 2)
        tx_kbps = round((tx_rate_bps * 8) / 1000, 2)
        rx_mbps = round((rx_rate_bps * 8) / 1_000_000, 3)
        tx_mbps = round((tx_rate_bps * 8) / 1_000_000, 3)

        # Update sparkline buffers
        time_label = time.strftime("%H:%M:%S", time.localtime(now))
        self.history_rx.append(rx_kbps)
        self.history_tx.append(tx_kbps)
        self.timestamps.append(time_label)

        if len(self.history_rx) > self.history_length:
            self.history_rx.pop(0)
            self.history_tx.pop(0)
            self.timestamps.pop(0)

        return {
            "rx_kbps": rx_kbps,
            "tx_kbps": tx_kbps,
            "rx_mbps": rx_mbps,
            "tx_mbps": tx_mbps,
            "interfaces": interface_stats,
            "history": {
                "timestamps": list(self.timestamps),
                "rx": list(self.history_rx),
                "tx": list(self.history_tx),
            },
        }


# Singleton tracker
bandwidth_tracker = BandwidthTracker()


def parse_endpoint(endpoint_str: str) -> Tuple[str, str]:
    """Splits '127.0.0.1:8080' or '[::]:22' or '*:22' into (address, port)."""
    endpoint_str = endpoint_str.strip()
    if not endpoint_str:
        return "*", "*"

    # Check for interface scope (e.g., 127.0.0.53%lo:53)
    if "%" in endpoint_str:
        endpoint_str = endpoint_str.split("%")[0] + ":" + endpoint_str.split(":")[-1]

    r_idx = endpoint_str.rfind(":")
    if r_idx == -1:
        return endpoint_str, "*"

    addr = endpoint_str[:r_idx].strip("[]")
    port = endpoint_str[r_idx + 1 :]
    return addr, port


def get_active_sockets(
    filter_proto: Optional[str] = None,
    filter_state: Optional[str] = None,
    filter_direction: Optional[str] = None,
    search: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes 'ss -H -t -u -a -p -n' to inspect real-time active sockets at the kernel level.
    Returns parsed connection list with direction detection and process metadata.
    """
    sockets: List[Dict[str, Any]] = []
    listening_ports = set()

    # Pass 1: Run ss command
    cmd = ["ss", "-H", "-t", "-u", "-a", "-p", "-n"]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3)
        raw_output = proc.stdout
    except Exception as e:
        logger.error(f"Failed to run ss command: {e}")
        return {"sockets": [], "summary": {}}

    lines = raw_output.strip().splitlines()

    # First pass: collect listening ports to accurately determine inbound vs outbound
    for line in lines:
        parts = line.split()
        if len(parts) >= 5 and parts[1].upper() == "LISTEN":
            _, lport = parse_endpoint(parts[4])
            if lport.isdigit():
                listening_ports.add(int(lport))

    # Second pass: parse and enrich
    inbound_count = 0
    outbound_count = 0
    listen_count = 0
    estab_count = 0

    for line in lines:
        parts = line.split()
        if len(parts) < 6:
            continue

        proto = parts[0].lower()
        state = parts[1].upper()
        recv_q = parts[2]
        send_q = parts[3]
        local_addr_str = parts[4]
        peer_addr_str = parts[5]

        # Extract process and PID if present
        pid = None
        process_name = "-"
        remainder = " ".join(parts[6:]) if len(parts) > 6 else ""
        user_match = SS_USERS_REGEX.search(remainder)
        if user_match:
            process_name = user_match.group(1)
            pid = int(user_match.group(2))

        local_ip, local_port = parse_endpoint(local_addr_str)
        remote_ip, remote_port = parse_endpoint(peer_addr_str)

        # Determine connection direction
        if state == "LISTEN":
            direction = "listen"
            listen_count += 1
        elif state == "ESTAB":
            estab_count += 1
            try:
                l_port_num = int(local_port) if local_port.isdigit() else 0
                if l_port_num in listening_ports:
                    direction = "inbound"
                    inbound_count += 1
                else:
                    direction = "outbound"
                    outbound_count += 1
            except Exception:
                direction = "other"
        else:
            direction = "other"

        # Apply Filters
        if filter_proto and proto != filter_proto.lower():
            continue
        if filter_state and state != filter_state.upper():
            continue
        if filter_direction and direction != filter_direction.lower():
            continue
        if search:
            q = search.lower()
            haystack = f"{local_ip} {local_port} {remote_ip} {remote_port} {process_name} {pid} {state}".lower()
            if q not in haystack:
                continue

        # Check for executable path from /proc/[pid]/exe if PID is known
        cmdline = ""
        exe_path = ""
        is_deleted_exe = False
        if pid:
            try:
                exe_target = os.readlink(f"/proc/{pid}/exe")
                exe_path = exe_target
                if "(deleted)" in exe_target:
                    is_deleted_exe = True
            except (FileNotFoundError, PermissionError):
                pass

            try:
                with open(f"/proc/{pid}/cmdline", "r", encoding="utf-8", errors="ignore") as f:
                    cmdline = f.read().replace("\x00", " ").strip()
            except Exception:
                pass

        sockets.append({
            "proto": proto,
            "state": state,
            "recv_q": recv_q,
            "send_q": send_q,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "pid": pid,
            "process_name": process_name,
            "exe_path": exe_path,
            "cmdline": cmdline[:150] if cmdline else "",
            "is_deleted_exe": is_deleted_exe,
            "direction": direction,
        })

    return {
        "sockets": sockets,
        "total": len(sockets),
        "summary": {
            "total_connections": len(lines),
            "established": estab_count,
            "listening": listen_count,
            "inbound": inbound_count,
            "outbound": outbound_count,
        },
    }


def get_top_ip_negotiations(limit: int = 25) -> List[Dict[str, Any]]:
    """
    Analyzes active kernel sockets to identify top remote IPs currently negotiating
    or holding network connections. Breaks down negotiation states (SYN_RECV, SYN_SENT,
    ESTAB, TIME_WAIT), target services, and flags aggressive handshakes.
    """
    from backend.app.modules.access import resolve_geo_ip

    raw_sockets = get_active_sockets()["sockets"]
    negotiations: Dict[str, Dict[str, Any]] = {}

    for s in raw_sockets:
        r_ip = s.get("remote_ip", "").strip()
        # Filter local loopbacks and wildcard listeners
        if not r_ip or r_ip in ("*", "0.0.0.0", "::", "127.0.0.1", "::1", "localhost"):
            continue

        if r_ip not in negotiations:
            negotiations[r_ip] = {
                "ip": r_ip,
                "total_negotiations": 0,
                "states": {
                    "SYN_RECV": 0,    # Inbound handshake negotiation / half-open
                    "SYN_SENT": 0,    # Outbound handshake initiation
                    "ESTAB": 0,       # Actively negotiated & connected
                    "TIME_WAIT": 0,   # Post-negotiation teardown
                    "OTHER": 0,
                },
                "ports": set(),
                "processes": set(),
                "protocols": set(),
            }

        entry = negotiations[r_ip]
        entry["total_negotiations"] += 1
        st = s.get("state", "").upper()
        if st in entry["states"]:
            entry["states"][st] += 1
        else:
            entry["states"]["OTHER"] += 1

        l_port = s.get("local_port")
        if l_port and l_port != "*":
            entry["ports"].add(str(l_port))

        p_name = s.get("process_name")
        if p_name and p_name != "-":
            entry["processes"].add(str(p_name))

        proto = s.get("proto")
        if proto:
            entry["protocols"].add(str(proto).upper())

    # Sort by total negotiations descending
    sorted_ips = sorted(negotiations.values(), key=lambda x: x["total_negotiations"], reverse=True)[:limit]

    results: List[Dict[str, Any]] = []
    for item in sorted_ips:
        geo = resolve_geo_ip(item["ip"])
        states = item["states"]

        # Anomaly / Risk classification
        if states["SYN_RECV"] >= 2:
            risk = "SUSPECT_SYN_PROBE"
            badge = "rose"
        elif item["total_negotiations"] >= 10:
            risk = "HIGH_CONCURRENCY"
            badge = "orange"
        elif states["ESTAB"] > 0:
            risk = "ESTABLISHED_FLOW"
            badge = "emerald"
        else:
            risk = "COOLDOWN_CLOSING"
            badge = "slate"

        results.append({
            "ip": item["ip"],
            "total_negotiations": item["total_negotiations"],
            "states": states,
            "target_ports": sorted(list(item["ports"]))[:8],
            "processes": sorted(list(item["processes"]))[:5],
            "protocols": sorted(list(item["protocols"])),
            "geo": geo,
            "risk_classification": risk,
            "badge_color": badge,
        })

    return results

