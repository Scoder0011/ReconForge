from __future__ import annotations

import json
from pathlib import Path

from core.logger import get_logger

logger = get_logger(__name__)


def parse(raw_path: Path) -> list[dict]:
    """Parse JSONL and skip broken lines without crashing the whole batch."""
    records: list[dict] = []
    text = raw_path.read_text(encoding="utf-8", errors="replace")
    stripped = text.strip()
    if not stripped:
        return records

    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        payload = None

    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                records.append(item)
        return records
    if isinstance(payload, dict):
        return [payload]

    for line_number, line in enumerate(text.splitlines(), start=1):
        cleaned = line.strip()
        if not cleaned:
            continue
        try:
            item = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            logger.warning("Skipping invalid JSONL line %s in %s: %s", line_number, raw_path, exc)
            continue
        if isinstance(item, dict):
            records.append(item)
    return records
