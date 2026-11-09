from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _strings(value: Any) -> list[str]:
    """Extract useful text values from common theHarvester list/object shapes."""
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        values: list[str] = []
        for item in value:
            values.extend(_strings(item))
        return values
    if isinstance(value, dict):
        for key in ("hostname", "host", "domain", "ip", "address", "value"):
            item = value.get(key)
            if isinstance(item, str) and item.strip():
                return [item.strip()]
    return []


def _find_values(payload: Any, keys: set[str]) -> list[str]:
    """Recursively collect values associated with any requested JSON key."""
    values: list[str] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            if str(key).lower() in keys:
                values.extend(_strings(value))
            else:
                values.extend(_find_values(value, keys))
    elif isinstance(payload, list):
        for item in payload:
            values.extend(_find_values(item, keys))
    return values


def parse(raw_path: Path) -> dict[str, list[str]]:
    """Parse theHarvester JSON output into deduplicated email, host, and IP lists."""
    empty = {"emails": [], "hosts": [], "ips": []}
    if not raw_path.exists():
        return empty
    try:
        payload = json.loads(raw_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return empty

    return {
        "emails": sorted(set(_find_values(payload, {"emails", "email"}))),
        "hosts": sorted(set(_find_values(payload, {"hosts", "host", "hostname", "subdomains"}))),
        "ips": sorted(set(_find_values(payload, {"ips", "ip", "addresses"}))),
    }
