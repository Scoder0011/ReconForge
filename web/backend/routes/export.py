from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse

from core.db import get_scan

router = APIRouter(prefix="/api/scans", tags=["export"])

_JSON_FILES = (
    "dns_records.json",
    "live_hosts.json",
    "screenshots.json",
    "js_findings.json",
    "param_findings.json",
    "content_discovery.json",
    "ports_and_tls.json",
    "vuln_findings.json",
    "cloud_and_secrets.json",
    "osint.json",
)


def _redact(value: Any) -> Any:
    secret_keys = {"secret", "token", "password", "credential", "apikey", "accesskey", "secretaccesskey", "raw", "rawv2", "match"}
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if str(key).replace("_", "").lower() in secret_keys else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


async def _scan_dir(scan_id: str) -> Path:
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    path = Path(scan["output_dir"]).resolve()
    if not path.is_relative_to(Path("output").resolve()):
        raise HTTPException(status_code=403, detail="Scan output is outside the configured output directory")
    return path


@router.get("/{scan_id}/export/{format}")
async def export_scan(scan_id: str, format: str):
    """Download a Markdown, HTML, or redacted aggregate JSON report."""
    if format not in {"md", "html", "json"}:
        raise HTTPException(status_code=404, detail="Unsupported export format")
    scan_dir = await _scan_dir(scan_id)
    if format == "md":
        path = scan_dir / "report.md"
        media_type = "text/markdown"
    elif format == "html":
        path = scan_dir / "report.html"
        media_type = "text/html"
    else:
        aggregate: dict[str, Any] = {}
        for filename in _JSON_FILES:
            path = scan_dir / filename
            if not path.is_file():
                continue
            try:
                aggregate[filename.removesuffix(".json")] = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
        return JSONResponse(_redact(aggregate), headers={"Content-Disposition": f'attachment; filename="{scan_id}.json"'})
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Report file not found")
    return FileResponse(path, media_type=media_type, filename=path.name)
