from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from core.logger import get_logger

if TYPE_CHECKING:
    from core.engine import ScanContext

logger = get_logger(__name__)


async def run_stage_11(ctx: "ScanContext", live_hosts: list[dict], urls: list[str]) -> dict[str, Any]:
    """Apply the strict vulnerability-scan consent gate without launching scanners."""
    del live_hosts, urls
    missing_flags = [
        flag
        for flag, enabled in (
            ("allow_active_scans", ctx.scope.allow_active_scans),
            ("allow_vuln_scans", ctx.scope.allow_vuln_scans),
        )
        if not enabled
    ]

    if missing_flags:
        reason = "required scope flags disabled: " + ", ".join(missing_flags)
        logger.info("stage 11 skipped — %s", reason)
        result: dict[str, Any] = {"status": "skipped", "reason": reason, "findings": {}}
    else:
        reason = "automated vulnerability scanner execution is not enabled in this safe implementation"
        logger.warning("stage 11 not run — %s", reason)
        result = {"status": "not_configured", "reason": reason, "findings": {}}

    ctx.results["vuln_findings"] = result
    output_path: Path = ctx.output_dir / "vuln_findings.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result
