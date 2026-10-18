"""Firewall management subsystem: kernel-level packet drops via nftables and iptables fallback."""
import os
import json
import time
import shutil
import logging
import subprocess
import ipaddress
from typing import Dict, Any, List, Optional
from pathlib import Path
from backend.app.core.config import settings
from backend.app.core.security import is_ip_whitelisted

logger = logging.getLogger("cybersentinel.firewall")

STATE_FILE = Path("/etc/cybersentinel/bans_metadata.json")
if not STATE_FILE.parent.exists():
    STATE_FILE = Path(__file__).resolve().parent.parent.parent.parent / "config" / "bans_metadata.json"


class FirewallManager:
    """
    Interfaces with Linux packet filtering primitives.
    Prefers modern atomic nftables with kernel timeouts; falls back to iptables/ipset.
    """

    def __init__(self):
        self.backend = self._detect_backend()
        self.metadata: Dict[str, Dict[str, Any]] = self._load_metadata()
        self._init_ruleset()

    def _detect_backend(self) -> str:
        pref = settings.get("firewall", {}).get("backend", "auto")
        if pref != "auto":
            return pref
        if shutil.which("nft"):
            return "nftables"
        if shutil.which("iptables"):
            return "iptables"
        return "none"

    def _load_metadata(self) -> Dict[str, Dict[str, Any]]:
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed loading ban metadata: {e}")
        return {}

    def _save_metadata(self) -> None:
        try:
            STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(self.metadata, f, indent=2)
        except Exception as e:
            logger.error(f"Failed saving ban metadata: {e}")

    def _init_ruleset(self) -> None:
        """Initializes the dedicated CyberSentinel table and chain."""
        if self.backend == "nftables":
            commands = [
                "nft add table inet cybersentinel 2>/dev/null",
                "nft 'add set inet cybersentinel banned_ipv4 { type ipv4_addr; flags timeout; }' 2>/dev/null",
                "nft 'add set inet cybersentinel banned_ipv6 { type ipv6_addr; flags timeout; }' 2>/dev/null",
                "nft 'add chain inet cybersentinel input { type filter hook input priority -150; policy accept; }' 2>/dev/null",
                "nft 'add rule inet cybersentinel input ip saddr @banned_ipv4 counter drop' 2>/dev/null",
                "nft 'add rule inet cybersentinel input ip6 saddr @banned_ipv6 counter drop' 2>/dev/null",
            ]
            for cmd in commands:
                try:
                    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception as e:
                    logger.warning(f"nft command failed during init: {e}")
            logger.info("Initialized nftables 'inet cybersentinel' drop table.")
        elif self.backend == "iptables":
            # Check or create custom chain
            subprocess.run("iptables -N CYBERSENTINEL 2>/dev/null", shell=True)
            subprocess.run(
                "iptables -C INPUT -j CYBERSENTINEL 2>/dev/null || iptables -I INPUT 1 -j CYBERSENTINEL",
                shell=True,
            )
            logger.info("Initialized iptables CYBERSENTINEL chain.")

    def block_ip(
        self,
        ip_str: str,
        duration_seconds: int = 0,
        reason: str = "Manual SOC Operator Block",
        actor: str = "operator",
        force: bool = False,
    ) -> Dict[str, Any]:
        """
        Bans an IP address at kernel level.
        duration_seconds: 0 = permanent; > 0 = timeout in seconds.
        force: bypass whitelist check if explicitly confirmed by user.
        """
        ip_str = ip_str.strip()
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return {"success": False, "error": f"Invalid IP address: '{ip_str}'"}

        # Whitelist protection
        if not force and is_ip_whitelisted(ip_str):
            return {
                "success": False,
                "error": f"IP {ip_str} is whitelisted! Cannot ban without force override.",
                "is_whitelisted": True,
            }

        is_v6 = ip_obj.version == 6
        set_name = "banned_ipv6" if is_v6 else "banned_ipv4"
        now = time.time()
        expires_at = (now + duration_seconds) if duration_seconds > 0 else 0

        # Execute kernel drop rule
        if self.backend == "nftables":
            if duration_seconds > 0:
                elem_spec = f"{ip_str} timeout {duration_seconds}s"
            else:
                elem_spec = ip_str
            cmd = f"nft 'add element inet cybersentinel {set_name} {{ {elem_spec} }}'"
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if res.returncode != 0:
                logger.error(f"nft add element error: {res.stderr}")
                return {"success": False, "error": res.stderr.strip()}
        elif self.backend == "iptables":
            cmd = f"iptables -I CYBERSENTINEL 1 -s {ip_str} -j DROP"
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if res.returncode != 0:
                return {"success": False, "error": res.stderr.strip()}
        else:
            return {"success": False, "error": "No supported firewall backend found"}

        # Store metadata
        self.metadata[ip_str] = {
            "ip": ip_str,
            "version": ip_obj.version,
            "created_at": now,
            "duration_seconds": duration_seconds,
            "expires_at": expires_at,
            "reason": reason,
            "actor": actor,
            "backend": self.backend,
        }
        self._save_metadata()

        logger.info(f"Successfully banned {ip_str} ({duration_seconds}s) via {self.backend}")
        return {
            "success": True,
            "ip": ip_str,
            "duration": duration_seconds,
            "expires_at": expires_at,
            "backend": self.backend,
        }

    def unblock_ip(self, ip_str: str) -> Dict[str, Any]:
        """Removes an active block rule from the firewall."""
        ip_str = ip_str.strip()
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            is_v6 = ip_obj.version == 6
            set_name = "banned_ipv6" if is_v6 else "banned_ipv4"
        except ValueError:
            return {"success": False, "error": f"Invalid IP address: '{ip_str}'"}

        removed = False
        if self.backend == "nftables":
            cmd = f"nft 'delete element inet cybersentinel {set_name} {{ {ip_str} }}'"
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if res.returncode == 0:
                removed = True
            else:
                logger.warning(f"nft delete warning: {res.stderr}")
        elif self.backend == "iptables":
            cmd = f"iptables -D CYBERSENTINEL -s {ip_str} -j DROP"
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if res.returncode == 0:
                removed = True

        if ip_str in self.metadata:
            del self.metadata[ip_str]
            self._save_metadata()
            removed = True

        logger.info(f"Unblocked {ip_str}")
        return {"success": True, "ip": ip_str, "removed": removed}

    def list_bans(self) -> Dict[str, Any]:
        """
        Lists all active bans, unifying CyberSentinel managed rules
        with any existing system bans (e.g., fail2ban / iptables drops).
        """
        now = time.time()
        managed_bans: List[Dict[str, Any]] = []
        live_ips = set()

        if self.backend == "nftables":
            for set_name in ["banned_ipv4", "banned_ipv6"]:
                try:
                    cmd = f"nft -j list set inet cybersentinel {set_name}"
                    res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=2)
                    if res.returncode == 0:
                        data = json.loads(res.stdout)
                        for item in data.get("nftables", []):
                            set_data = item.get("set", {})
                            for elem in set_data.get("elem", []):
                                if isinstance(elem, dict) and "elem" in elem:
                                    elem_info = elem["elem"]
                                    val = elem_info.get("val")
                                    expires = elem_info.get("expires", 0)
                                    timeout = elem_info.get("timeout", 0)
                                elif isinstance(elem, str):
                                    val = elem
                                    expires = 0
                                    timeout = 0
                                else:
                                    continue

                                if val:
                                    live_ips.add(val)
                                    meta = self.metadata.get(val, {})
                                    managed_bans.append({
                                        "ip": val,
                                        "source": "cybersentinel",
                                        "created_at": meta.get("created_at", now),
                                        "duration": timeout or meta.get("duration_seconds", 0),
                                        "expires_in_seconds": expires,
                                        "expires_at": (now + expires) if expires > 0 else 0,
                                        "reason": meta.get("reason", "CyberSentinel Kernel Drop"),
                                        "actor": meta.get("actor", "system"),
                                        "backend": "nftables",
                                    })
                except Exception as e:
                    logger.error(f"Error reading nft set {set_name}: {e}")

        # Check for system bans (e.g. fail2ban or standard iptables drops)
        system_bans: List[Dict[str, Any]] = []
        try:
            # Check iptables drops
            res = subprocess.run(
                ["iptables", "-L", "INPUT", "-n", "-v", "--line-numbers"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines()[2:]:
                    parts = line.split()
                    if len(parts) >= 9 and parts[3] == "DROP":
                        src = parts[8]
                        if src != "0.0.0.0/0" and src not in live_ips:
                            system_bans.append({
                                "ip": src,
                                "source": "iptables_system",
                                "pkts_dropped": parts[1],
                                "bytes_dropped": parts[2],
                                "reason": "System Firewall DROP",
                            })
        except Exception:
            pass

        # Check fail2ban nft sets if any
        try:
            res = subprocess.run(["nft", "-j", "list", "ruleset"], capture_output=True, text=True, timeout=2)
            if res.returncode == 0 and "f2b-table" in res.stdout:
                data = json.loads(res.stdout)
                for item in data.get("nftables", []):
                    s = item.get("set", {})
                    if "f2b" in s.get("table", ""):
                        for elem in s.get("elem", []):
                            ip_val = elem if isinstance(elem, str) else (elem.get("elem", {}).get("val") if isinstance(elem, dict) else None)
                            if ip_val and ip_val not in live_ips:
                                system_bans.append({
                                    "ip": ip_val,
                                    "source": "fail2ban",
                                    "reason": f"Fail2ban Jail ({s.get('name', 'sshd')})",
                                })
        except Exception:
            pass

        return {
            "backend": self.backend,
            "managed_bans": managed_bans,
            "system_bans": system_bans[:50],  # cap external system bans for performance
            "total_managed": len(managed_bans),
            "total_system": len(system_bans),
            "total_banned": len(managed_bans) + len(system_bans),
        }

    def get_whitelist(self) -> List[str]:
        return settings.whitelist

    def add_to_whitelist(self, item: str) -> Dict[str, Any]:
        item = item.strip()
        current = list(settings.whitelist)
        if item in current:
            return {"success": True, "message": "Already in whitelist", "whitelist": current}
        current.append(item)
        settings.update({"firewall": {"whitelist": current}})
        return {"success": True, "whitelist": current}

    def remove_from_whitelist(self, item: str) -> Dict[str, Any]:
        item = item.strip()
        current = list(settings.whitelist)
        if item in current:
            current.remove(item)
            settings.update({"firewall": {"whitelist": current}})
        return {"success": True, "whitelist": current}


# Global instance
firewall_manager = FirewallManager()
