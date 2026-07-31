#!/usr/bin/env python3
"""
Anti-DDoS Flood Detector - entry point.

Usage:
    sudo python3 main.py --config config.yaml

Requires root/administrator privileges because raw packet capture and
iptables rule management both need elevated access.
"""

from __future__ import annotations

import argparse
import os
import sys

from src.detector import FloodDetector
from src.logger_setup import get_logger
from src.mitigator import Mitigator
from src.sniffer import PacketSniffer
from src.utils import load_config


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Real-time network flood (SYN/UDP/ICMP) detector and mitigator."
    )
    parser.add_argument(
        "-c", "--config",
        default="config.yaml",
        help="Path to configuration file (default: config.yaml)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    logger = get_logger("anti_ddos", config["logging"])

    if os.name == "posix" and os.geteuid() != 0:
        logger.error("This tool requires root privileges for packet capture and iptables.")
        return 1

    mitigator = Mitigator(config, logger)
    detector = FloodDetector(config, logger, on_flood_detected=mitigator.handle_flood)
    sniffer = PacketSniffer(
        interface=config["network"]["interface"],
        bpf_filter=config["network"].get("bpf_filter", "ip"),
        logger=logger,
    )

    logger.info("Anti-DDoS Flood Detector started. Press Ctrl+C to stop.")
    try:
        sniffer.start(handler=detector.process_packet)
    except KeyboardInterrupt:
        logger.info("Shutting down gracefully.")
    except OSError as exc:
        logger.error("Capture failed: %s", exc)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
