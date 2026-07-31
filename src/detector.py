"""
Core flood-detection engine.

The detector keeps a per-source-IP, per-protocol sliding window of packet
timestamps. When the number of packets from a single IP within the
configured time window exceeds the threshold, an alert is raised and,
if mitigation is enabled, the offending IP is handed off to the
Mitigator for blocking.

This is a classic rate-based anomaly detector: it does not attempt deep
packet inspection or signature matching, which keeps it fast enough to
run inline on live traffic.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Callable

from src.utils import is_whitelisted

FloodType = str  # "syn_flood" | "udp_flood" | "icmp_flood"


class FloodDetector:
    def __init__(
        self,
        config: dict,
        logger: logging.Logger,
        on_flood_detected: Callable[[str, FloodType, int], None] | None = None,
    ) -> None:
        """
        Args:
            config: Full parsed config.yaml.
            logger: Shared logger instance.
            on_flood_detected: Callback invoked as
                on_flood_detected(source_ip, flood_type, packet_count)
                whenever a threshold is exceeded. Used to trigger mitigation.
        """
        self.thresholds = config["thresholds"]
        self.whitelist = config.get("whitelist", [])
        self.logger = logger
        self.on_flood_detected = on_flood_detected

        # windows[flood_type][ip] -> deque of packet timestamps
        self._windows: dict[FloodType, dict[str, deque]] = {
            "syn_flood": defaultdict(deque),
            "udp_flood": defaultdict(deque),
            "icmp_flood": defaultdict(deque),
        }

        # Track which (ip, flood_type) pairs already triggered an alert
        # so we don't spam callbacks every single packet while still flooding.
        self._already_alerted: set[tuple[str, FloodType]] = set()

    def process_packet(self, src_ip: str, flood_type: FloodType) -> None:
        """Register one observed packet and evaluate thresholds.

        Args:
            src_ip: Source IP address extracted from the packet.
            flood_type: One of "syn_flood", "udp_flood", "icmp_flood".
        """
        if flood_type not in self._windows:
            return

        if is_whitelisted(src_ip, self.whitelist):
            return

        window = self._windows[flood_type][src_ip]
        now = time.monotonic()
        window.append(now)

        time_window = self.thresholds[flood_type]["time_window"]
        limit = self.thresholds[flood_type]["packet_count"]

        # Evict timestamps that fell outside the sliding window
        while window and now - window[0] > time_window:
            window.popleft()

        count = len(window)

        if count >= limit:
            key = (src_ip, flood_type)
            if key not in self._already_alerted:
                self._already_alerted.add(key)
                self.logger.warning(
                    "Flood detected: type=%s source=%s count=%d/%ds",
                    flood_type, src_ip, count, time_window,
                )
                if self.on_flood_detected:
                    self.on_flood_detected(src_ip, flood_type, count)
        else:
            # Window dropped back below threshold -> allow future re-alerting
            self._already_alerted.discard((src_ip, flood_type))

    def reset(self) -> None:
        """Clear all tracked state. Mainly useful for tests."""
        for windows in self._windows.values():
            windows.clear()
        self._already_alerted.clear()
