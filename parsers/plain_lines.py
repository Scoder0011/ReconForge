from __future__ import annotations

from pathlib import Path


def parse(raw_path: Path) -> list[str]:
    """Read plain-text output, remove comments/empty entries, and preserve first-seen order."""
    seen: set[str] = set()
    items: list[str] = []
    with raw_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            cleaned = line.strip()
            if not cleaned or cleaned.startswith("#"):
                continue
            normalized = cleaned.lower()
            if normalized in seen:
                continue
            seen.add(normalized)
            items.append(normalized)
    return items
