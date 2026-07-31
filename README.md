# Anti-DDoS Flood Detector

A lightweight, real-time network flood detection and mitigation tool written in Python. It monitors live traffic for SYN, UDP, and ICMP flood patterns and can automatically block offending source IPs via `iptables`.

## Features

- **Real-time packet capture** using Scapy, filtered at the kernel level (BPF) for low overhead.
- **Sliding-window rate detection** per source IP and per protocol (SYN / UDP / ICMP), independently configurable.
- **Automatic mitigation** — offending IPs are blocked via `iptables` and automatically unblocked after a configurable duration.
- **Whitelist support** for trusted hosts and CIDR ranges (gateways, monitoring servers, etc.).
- **Dry-run mode** — run detection-only without touching the firewall.
- **Rotating log files** with configurable retention and log level.
- **Fully unit-tested** detection engine with a mocked clock for deterministic tests.

## How It Works

For each incoming packet, the sniffer classifies it as a SYN, UDP, or ICMP packet and forwards the source IP to the detection engine. The engine keeps a sliding time-window of timestamps per `(source_ip, protocol)` pair. If the number of packets from a single IP within the configured window exceeds the threshold, an alert is raised and, if mitigation is enabled, the IP is handed to the mitigator for blocking.

```
Sniffer (Scapy) --> FloodDetector (sliding window) --> Mitigator (iptables)
                              |
                              v
                        Rotating logs
```

## Project Structure

```
anti-ddos-flood-detector/
├── main.py               # CLI entry point
├── config.yaml            # Thresholds, network interface, mitigation settings
├── requirements.txt
├── src/
│   ├── sniffer.py          # Packet capture & classification (Scapy)
│   ├── detector.py         # Sliding-window flood detection engine
│   ├── mitigator.py        # iptables-based blocking / auto-unblock
│   ├── logger_setup.py     # Shared rotating-file logger
│   └── utils.py            # Config loader, whitelist matching
└── tests/
    └── test_detector.py    # Unit tests for the detection engine
```

## Installation

```bash
git clone https://github.com/<your-username>/anti-ddos-flood-detector.git
cd anti-ddos-flood-detector
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

Edit `config.yaml` to match your network interface and desired thresholds, then run with root privileges (required for raw packet capture and `iptables`):

```bash
sudo python3 main.py --config config.yaml
```

### Dry-run (detection only, no blocking)

Set `mitigation.enabled: false` in `config.yaml` to log flood events without modifying the firewall.

## Configuration Reference

| Section                | Key              | Description                                      |
|-------------------------|------------------|---------------------------------------------------|
| `network.interface`     | string           | Network interface to capture on                   |
| `thresholds.<type>`     | packet_count, time_window | Packets/seconds that define a flood      |
| `mitigation.enabled`    | bool             | Enable/disable automatic blocking                  |
| `mitigation.block_duration` | int          | Seconds an IP stays blocked                        |
| `whitelist`              | list             | IPs/CIDR ranges never blocked                      |

## Running Tests

```bash
python3 -m unittest discover tests
```

## Disclaimer

This tool is intended for defending infrastructure you own or are authorized to protect. It performs rate-based detection and is not a substitute for a dedicated upstream DDoS scrubbing service for large-scale volumetric attacks.

## License

Released under the [MIT License](LICENSE).
# Anti-DDoS-Flood-Detector