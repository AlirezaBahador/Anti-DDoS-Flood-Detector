"""
Live packet capture layer built on Scapy.

Isolating capture logic here keeps `FloodDetector` protocol-agnostic and
testable without needing raw sockets or root privileges.
"""

from __future__ import annotations

import logging
from typing import Callable

from scapy.all import ICMP, IP, TCP, UDP, sniff  # type: ignore

PacketHandler = Callable[[str, str], None]  # (src_ip, flood_type)


class PacketSniffer:
    def __init__(self, interface: str, bpf_filter: str, logger: logging.Logger) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.logger = logger

    def start(self, handler: PacketHandler) -> None:
        """Start capturing packets, blocking until interrupted.

        Args:
            handler: Callback invoked as handler(src_ip, flood_type) for
                every packet that matches a recognized flood category.
        """
        self.logger.info(
            "Starting capture on interface=%s filter='%s'",
            self.interface, self.bpf_filter,
        )
        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=lambda pkt: self._classify_and_dispatch(pkt, handler),
            store=False,
        )

    @staticmethod
    def _classify_and_dispatch(pkt, handler: PacketHandler) -> None:
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src

        if pkt.haslayer(TCP) and pkt[TCP].flags & 0x02:  # SYN flag set
            handler(src_ip, "syn_flood")
        elif pkt.haslayer(UDP):
            handler(src_ip, "udp_flood")
        elif pkt.haslayer(ICMP):
            handler(src_ip, "icmp_flood")
