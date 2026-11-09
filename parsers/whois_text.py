from __future__ import annotations

import re
from pathlib import Path

_KEY_VALUE = re.compile(r"^\s*([^:]+?)\s*:\s*(.*?)\s*$")


def parse(raw_path: Path) -> dict[str, str | list[str]]:
    """Parse WHOIS key/value lines, preserving repeated fields as lists."""
    if not raw_path.exists():
        return {}

    result: dict[str, str | list[str]] = {}
    try:
        lines = raw_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return result

    for line in lines:
        match = _KEY_VALUE.match(line)
        if match is None:
            continue
        key = " ".join(match.group(1).strip().lower().split())
        value = match.group(2).strip()
        if not key or not value:
            continue
        previous = result.get(key)
        if previous is None:
            result[key] = value
        elif isinstance(previous, list):
            previous.append(value)
        else:
            result[key] = [previous, value]

    return result
