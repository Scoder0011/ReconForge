from __future__ import annotations

import re
from pathlib import Path


_RESULT_LINE = re.compile(
    r"^(?P<url>\S+)\s+\(Status:\s*(?P<status>\d+)\)"
    r"(?:\s+\[Size:\s*(?P<size>\d+)\])?$"
)


def parse(raw_path: Path) -> list[dict]:
    """Parse Gobuster's expanded directory-mode output into normalized records."""
    records: list[dict] = []
    try:
        lines = Path(raw_path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return records

    for line in lines:
        match = _RESULT_LINE.fullmatch(line.strip())
        if match is None:
            continue
        record: dict[str, int | str] = {
            "url": match.group("url"),
            "status": int(match.group("status")),
        }
        if match.group("size") is not None:
            record["length"] = int(match.group("size"))
        records.append(record)
    return records
