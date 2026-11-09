from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from core.logger import get_logger

logger = get_logger(__name__)


def _parse_jsonl(path: Path) -> list[dict]:
    """Parse gowitness JSONL output if the installed version writes that format instead of SQLite."""
    items: list[dict] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                cleaned = line.strip()
                if not cleaned:
                    continue
                try:
                    value = json.loads(cleaned)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict):
                    items.append(value)
    except OSError as exc:
        logger.warning("Unable to read gowitness JSONL output %s: %s", path, exc)
    return items


def parse(db_or_output_path: Path) -> list[dict]:
    """Read gowitness SQLite or JSON output and normalize it into screenshot records."""
    path = Path(db_or_output_path)
    if not path.exists():
        return []

    lower_name = path.name.lower()
    if lower_name.endswith(".json") or lower_name.endswith(".jsonl"):
        return _parse_jsonl(path)

    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT url, response_code, title, filename FROM results WHERE failed IS NULL OR failed = 0 ORDER BY id"
            ).fetchall()
    except (sqlite3.DatabaseError, OSError) as exc:
        logger.warning("Unable to read gowitness database %s: %s", path, exc)
        return []

    screenshots: list[dict] = []
    for row in rows:
        url = str(row["url"] or "").strip()
        filename = str(row["filename"] or "").strip()
        if not url:
            continue
        screenshot_path = filename
        if filename and not Path(filename).is_absolute():
            screenshot_path = str(path.parent / filename)
        screenshots.append(
            {
                "url": url,
                "screenshot_path": screenshot_path,
                "status_code": row["response_code"],
                "title": row["title"],
            }
        )
    return screenshots
