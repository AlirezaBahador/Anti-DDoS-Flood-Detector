"""
Mitigation layer: turns a detection event into a concrete blocking action.

Two backends are supported:
  - "iptables": inserts a DROP rule for the offending IP via subprocess,
     and schedules automatic removal after `block_duration` seconds.
  - "log_only": records the event without touching the firewall, useful
     for dry runs or environments where the process doesn't have the
     privileges to modify iptables.
"""

from __future__ import annotations

import logging
import subprocess
import threading
import time


class Mitigator:
    def __init__(self, config: dict, logger: logging.Logger) -> None:
        mitigation_cfg = config.get("mitigation", {})
        self.enabled: bool = mitigation_cfg.get("enabled", False)
        self.method: str = mitigation_cfg.get("method", "log_only")
        self.block_duration: int = int(mitigation_cfg.get("block_duration", 300))
        self.logger = logger

        self._blocked_ips: dict[str, float] = {}  # ip -> unblock_timestamp
        self._lock = threading.Lock()

    def handle_flood(self, source_ip: str, flood_type: str, packet_count: int) -> None:
        """Entry point called by the detector when a threshold is exceeded."""
        if not self.enabled:
            self.logger.info(
                "Mitigation disabled (dry-run). Would block %s (%s, %d pkts).",
                source_ip, flood_type, packet_count,
            )
            return

        with self._lock:
            if source_ip in self._blocked_ips:
                return  # already blocked, nothing to do

        if self.method == "iptables":
            self._block_with_iptables(source_ip)
        else:
            self.logger.info("Log-only mode: flagged %s for %s", source_ip, flood_type)

    def _block_with_iptables(self, ip: str) -> None:
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True,
            )
            self.logger.warning("Blocked %s via iptables for %ds", ip, self.block_duration)
        except subprocess.CalledProcessError as exc:
            self.logger.error("Failed to block %s: %s", ip, exc.stderr.decode().strip())
            return
        except FileNotFoundError:
            self.logger.error("iptables binary not found. Is it installed and in PATH?")
            return

        with self._lock:
            self._blocked_ips[ip] = time.monotonic() + self.block_duration

        timer = threading.Timer(self.block_duration, self._unblock, args=[ip])
        timer.daemon = True
        timer.start()

    def _unblock(self, ip: str) -> None:
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True,
            )
            self.logger.info("Unblocked %s (block duration expired)", ip)
        except subprocess.CalledProcessError as exc:
            self.logger.error("Failed to unblock %s: %s", ip, exc.stderr.decode().strip())
        finally:
            with self._lock:
                self._blocked_ips.pop(ip, None)

    def currently_blocked(self) -> list[str]:
        """Return the list of IPs currently under an active block."""
        with self._lock:
            return list(self._blocked_ips.keys())
