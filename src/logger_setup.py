"""
Centralized logging configuration.

Provides a single `get_logger` factory so every module in the project
shares the same rotating-file + console handler setup instead of each
module configuring logging independently.
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler


def get_logger(name: str, config: dict) -> logging.Logger:
    """Create (or reuse) a configured logger instance.

    Args:
        name: Logger name, typically __name__ of the calling module.
        config: The "logging" section of config.yaml.

    Returns:
        A logging.Logger with console + rotating file handlers attached.
    """
    logger = logging.getLogger(name)

    # Avoid attaching duplicate handlers if get_logger is called more than once
    if logger.handlers:
        return logger

    level = getattr(logging, str(config.get("log_level", "INFO")).upper(), logging.INFO)
    logger.setLevel(level)

    log_file = config.get("log_file", "logs/flood_detector.log")
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=int(config.get("max_bytes", 5 * 1024 * 1024)),
        backupCount=int(config.get("backup_count", 5)),
        encoding="utf-8",
    )
    file_handler.setFormatter(fmt)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    logger.propagate = False

    return logger
