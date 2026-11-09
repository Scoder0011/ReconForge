from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from core.db import get_scan

router = APIRouter(prefix="/api/scans", tags=["results"])

_RESULT_FILES = {
    "subdomains": "subdomains.txt",
    "dns": "dns_records.json",
    "live_hosts": "live_hosts.json",
    "screenshots": "screenshots.json",
    "js": "js_findings.json",
    "parameters": "param_findings.json",
    "content_discovery": "content_discovery.json",
    "ports": "ports_and_tls.json",
    "vulnerabilities": "vuln_findings.json",
    "cloud_secrets": "cloud_and_secrets.json",
    "osint": "osint.json",
}


async def _scan_dir(scan_id: str) -> Path:
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    path = Path(scan["output_dir"]).resolve()
    allowed_root = Path("output").resolve()
    if not path.is_relative_to(allowed_root):
        raise HTTPException(status_code=403, detail="Scan output is outside the configured output directory")
    return path


def _redact_secrets(value: Any) -> Any:
    """Prevent known secret-value fields from being returned by the local result API."""
    secret_keys = {"secret", "token", "password", "credential", "apikey", "accesskey", "secretaccesskey", "raw", "rawv2", "match"}
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if str(key).replace("_", "").lower() in secret_keys else _redact_secrets(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_secrets(item) for item in value]
    return value


@router.get("/{scan_id}/results/{stage}")
async def scan_result(scan_id: str, stage: str) -> Any:
    """Read an allowlisted result file for a recorded scan."""
    filename = _RESULT_FILES.get(stage)
    if filename is None:
        raise HTTPException(status_code=404, detail="Unknown result stage")
    path = await _scan_dir(scan_id) / filename
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Result file not found")
    if filename.endswith(".txt"):
        return {"items": path.read_text(encoding="utf-8", errors="replace").splitlines()}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail=f"Could not read result file: {exc}") from exc
    return _redact_secrets(payload)


@router.get("/{scan_id}/report")
async def scan_report(scan_id: str) -> FileResponse:
    """Serve the generated HTML report or explain why it is not available yet."""
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["status"] == "running":
        raise HTTPException(
            status_code=409,
            detail="The scan is still running. The HTML report is available after it completes.",
        )

    path = await _scan_dir(scan_id) / "report.html"
    if not path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Report not found. The scan may have been interrupted before report generation.",
        )
    return FileResponse(path, media_type="text/html")
