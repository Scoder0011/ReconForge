from __future__ import annotations

import json
from pathlib import Path

from core.logger import get_logger

logger = get_logger(__name__)


def parse(raw_path: Path) -> list[dict]:
    """Parse ffuf JSON output and normalize it into compact findings records."""
    path = Path(raw_path)
    if not path.exists():
        return []

    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Unable to read ffuf JSON output %s: %s", path, exc)
        return []

    if not isinstance(payload, dict):
        return []
    results = payload.get("results", [])
    if not isinstance(results, list):
        return []

    normalized: list[dict] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        url = str(result.get("url") or "").strip()
        if not url:
            continue
        normalized.append(
            {
                "url": url,
                "status": result.get("status"),
                "length": result.get("length"),
                "words": result.get("words"),
                "lines": result.get("lines"),
            }
        )
    return normalized
