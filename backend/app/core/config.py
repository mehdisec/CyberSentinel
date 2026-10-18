"""Configuration manager for CyberSentinel Security Daemon."""
import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, List

logger = logging.getLogger("cybersentinel.config")

# Base directory paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
CONFIG_PATHS = [
    Path("/etc/cybersentinel/config.json"),
    BASE_DIR / "config" / "config.json",
    BASE_DIR / "config" / "config.example.json",
]

DEFAULT_CONFIG: Dict[str, Any] = {
    "server": {
        "host": "0.0.0.0",
        "port": 9090,
        "auth_enabled": False,
        "admin_token": "aegis-secret-soc-key-change-me",
    },
    "firewall": {
        "backend": "auto",
        "whitelist": [
            "127.0.0.1",
            "::1",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ],
    },
    "alerts": {
        "failed_logins_threshold_1h": 10,
        "bandwidth_spike_mbps": 100,
        "threat_score_high": 65,
    },
    "notifications": {
        "enabled": False,
        "discord_webhook_url": "",
        "telegram_bot_token": "",
        "telegram_chat_id": "",
        "generic_webhook_url": "",
    },
    "fim": {
        "baseline_file": str(BASE_DIR / "config" / "fim_baseline.json"),
        "paths": [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/ssh/sshd_config",
            "/etc/hosts",
            "/etc/crontab",
            "/etc/pam.d/common-auth",
            "/root/.ssh/authorized_keys",
        ],
    },
}


class ConfigManager:
    """Manages active runtime configuration and persistent updates."""

    def __init__(self):
        self.config_path: Path = self._locate_config()
        self.data: Dict[str, Any] = self._load()

    def _locate_config(self) -> Path:
        for p in CONFIG_PATHS:
            if p.exists():
                return p
        fallback = BASE_DIR / "config" / "config.json"
        fallback.parent.mkdir(parents=True, exist_ok=True)
        return fallback

    def _load(self) -> Dict[str, Any]:
        cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    # Merge top-level dicts
                    for key, val in loaded.items():
                        if isinstance(val, dict) and key in cfg:
                            cfg[key].update(val)
                        else:
                            cfg[key] = val
                logger.info(f"Loaded configuration from {self.config_path}")
            except Exception as e:
                logger.warning(f"Failed parsing {self.config_path}, falling back to defaults: {e}")
        else:
            self._save(cfg)
        return cfg

    def _save(self, data: Dict[str, Any]) -> None:
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            logger.info(f"Persisted configuration to {self.config_path}")
        except Exception as e:
            logger.error(f"Failed saving configuration to {self.config_path}: {e}")

    def get(self, section: str, default: Any = None) -> Any:
        return self.data.get(section, default)

    def update(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update runtime settings and save to disk."""
        for section, values in updates.items():
            if isinstance(values, dict) and section in self.data and isinstance(self.data[section], dict):
                self.data[section].update(values)
            else:
                self.data[section] = values
        self._save(self.data)
        return self.data

    @property
    def host(self) -> str:
        return os.environ.get("CYBERSENTINEL_HOST", self.data["server"].get("host", "0.0.0.0"))

    @property
    def port(self) -> int:
        return int(os.environ.get("CYBERSENTINEL_PORT", self.data["server"].get("port", 9090)))

    @property
    def auth_enabled(self) -> bool:
        return bool(self.data["server"].get("auth_enabled", False))

    @property
    def admin_token(self) -> str:
        return os.environ.get("CYBERSENTINEL_TOKEN", self.data["server"].get("admin_token", "admin"))

    @property
    def whitelist(self) -> List[str]:
        return self.data["firewall"].get("whitelist", [])

    @property
    def fim_paths(self) -> List[str]:
        return self.data["fim"].get("paths", [])

    @property
    def fim_baseline_file(self) -> Path:
        return Path(self.data["fim"].get("baseline_file", str(BASE_DIR / "config" / "fim_baseline.json")))


# Global singleton instance
settings = ConfigManager()
