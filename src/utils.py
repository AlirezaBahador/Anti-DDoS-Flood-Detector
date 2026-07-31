"""Small shared helpers: config loading and IP whitelist checks."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

import yaml


def load_config(path: str | Path) -> dict[str, Any]:
    """Load and validate the YAML configuration file.

    Args:
        path: Path to config.yaml.

    Returns:
        Parsed configuration as a dictionary.

    Raises:
        FileNotFoundError: If the config file does not exist.
        ValueError: If required top-level sections are missing.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    required_sections = ("network", "thresholds", "mitigation", "logging")
    missing = [s for s in required_sections if s not in config]
    if missing:
        raise ValueError(f"Missing required config section(s): {', '.join(missing)}")

    return config


def is_whitelisted(ip: str, whitelist: list[str]) -> bool:
    """Check whether an IP address is in the configured whitelist.

    Supports both individual IPs and CIDR ranges (e.g. "10.0.0.0/8").
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    for entry in whitelist or []:
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue

    return False
