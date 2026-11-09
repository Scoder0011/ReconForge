from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException

from core.db import get_scan, list_scans

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.get("")
async def scans_index() -> list[dict]:
    """List scans previously launched from the CLI."""
    return await list_scans()


@router.get("/{scan_id}")
async def scan_detail(scan_id: str) -> dict:
    """Return stored scan metadata and a compact summary of available results."""
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    output_dir = Path(scan["output_dir"])
    if not output_dir.resolve().is_relative_to(Path("output").resolve()):
        raise HTTPException(status_code=403, detail="Scan output is outside the configured output directory")
    counts: dict[str, int] = {}
    count_files = {
        "subdomains": "subdomains.txt",
        "resolved": "dns_records.json",
        "live_hosts": "live_hosts.json",
        "screenshots": "screenshots.json",
        "urls": "urls.txt",
    }
    for key, filename in count_files.items():
        path = output_dir / filename
        if not path.is_file():
            continue
        if filename.endswith(".txt"):
            counts[key] = sum(1 for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())
        else:
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            counts[key] = len(payload) if isinstance(payload, list) else 0
    scan["counts"] = counts
    return scan
