"""Unit tests for FloodDetector using a mocked clock for determinism."""

import logging
import unittest
from unittest.mock import patch

from src.detector import FloodDetector

BASE_CONFIG = {
    "thresholds": {
        "syn_flood": {"packet_count": 5, "time_window": 10},
        "udp_flood": {"packet_count": 5, "time_window": 10},
        "icmp_flood": {"packet_count": 5, "time_window": 10},
    },
    "whitelist": ["10.0.0.1"],
}


def _silent_logger() -> logging.Logger:
    logger = logging.getLogger("test_detector")
    logger.addHandler(logging.NullHandler())
    return logger


class TestFloodDetector(unittest.TestCase):
    def setUp(self) -> None:
        self.alerts: list[tuple[str, str, int]] = []
        self.detector = FloodDetector(
            BASE_CONFIG,
            _silent_logger(),
            on_flood_detected=lambda ip, ftype, count: self.alerts.append((ip, ftype, count)),
        )

    @patch("src.detector.time.monotonic")
    def test_no_alert_below_threshold(self, mock_time) -> None:
        mock_time.return_value = 0.0
        for _ in range(4):  # below limit of 5
            self.detector.process_packet("1.2.3.4", "syn_flood")

        self.assertEqual(self.alerts, [])

    @patch("src.detector.time.monotonic")
    def test_alert_fires_at_threshold(self, mock_time) -> None:
        mock_time.return_value = 0.0
        for _ in range(5):
            self.detector.process_packet("1.2.3.4", "syn_flood")

        self.assertEqual(len(self.alerts), 1)
        self.assertEqual(self.alerts[0], ("1.2.3.4", "syn_flood", 5))

    @patch("src.detector.time.monotonic")
    def test_alert_not_duplicated_while_still_flooding(self, mock_time) -> None:
        mock_time.return_value = 0.0
        for _ in range(8):  # well above the threshold of 5
            self.detector.process_packet("1.2.3.4", "syn_flood")

        self.assertEqual(len(self.alerts), 1)

    @patch("src.detector.time.monotonic")
    def test_old_packets_expire_outside_window(self, mock_time) -> None:
        mock_time.return_value = 0.0
        for _ in range(4):
            self.detector.process_packet("1.2.3.4", "syn_flood")

        # Jump past the 10s window; old packets should be evicted
        mock_time.return_value = 20.0
        self.detector.process_packet("1.2.3.4", "syn_flood")

        self.assertEqual(self.alerts, [])

    @patch("src.detector.time.monotonic")
    def test_whitelisted_ip_never_alerts(self, mock_time) -> None:
        mock_time.return_value = 0.0
        for _ in range(10):
            self.detector.process_packet("10.0.0.1", "syn_flood")

        self.assertEqual(self.alerts, [])

    @patch("src.detector.time.monotonic")
    def test_different_protocols_tracked_independently(self, mock_time) -> None:
        mock_time.return_value = 0.0
        for _ in range(5):
            self.detector.process_packet("1.2.3.4", "syn_flood")
        for _ in range(3):
            self.detector.process_packet("1.2.3.4", "udp_flood")

        types_alerted = {a[1] for a in self.alerts}
        self.assertEqual(types_alerted, {"syn_flood"})


if __name__ == "__main__":
    unittest.main()
