from __future__ import annotations

import logging
from pathlib import Path

import yaml


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger that can read a log level from config/config.yaml."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.propagate = False

    config_path = Path(__file__).resolve().parents[1] / "config" / "config.yaml"
    if config_path.exists():
        try:
            with config_path.open("r", encoding="utf-8") as handle:
                config = yaml.safe_load(handle) or {}
            level_name = str(config.get("log_level", "INFO")).upper()
            logger.setLevel(getattr(logging, level_name, logging.INFO))
        except Exception:
            logger.setLevel(logging.INFO)
    return logger
