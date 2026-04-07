"""
Centralized configuration for the Home IDS.
Loads from environment variables with sensible defaults.
"""

import os
from dataclasses import dataclass
from typing import Optional

try:
    from dotenv import load_dotenv
except ImportError:  # Optional dependency in case users don't install extras
    load_dotenv = None


if load_dotenv:
    # Load local .env if present so Quickstart works without manual exports.
    load_dotenv()


def _env(name: str, default: Optional[str]) -> Optional[str]:
    return os.getenv(name, default)


@dataclass
class Settings:
    cidr: str = _env("IDS_CIDR", "192.168.1.0/24")
    interface: Optional[str] = _env("IDS_INTERFACE", None)
    scan_interval: int = int(_env("IDS_SCAN_INTERVAL", "300"))
    alert_log: str = _env("IDS_ALERT_LOG", "alerts.log")
    known_hosts: str = _env("IDS_KNOWN_HOSTS", "known_hosts.json")
    flask_host: str = _env("IDS_HOST", "0.0.0.0")
    flask_port: int = int(_env("IDS_PORT", "5000"))
    nmap_path: str = _env("IDS_NMAP_PATH", "nmap")


def get_settings() -> Settings:
    return Settings()
