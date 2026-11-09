from __future__ import annotations

import importlib
import json
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from core.logger import get_logger
from core.runner import run_tools_parallel

if TYPE_CHECKING:
    from core.engine import ScanContext

logger = get_logger(__name__)


async def run_stage_04(ctx: "ScanContext", resolved_records: list[dict]) -> list[dict]:
    """Probe resolved hosts with httpx and persist live HTTP metadata."""
    if not resolved_records:
        ctx.results["live_hosts"] = []
        return []

    hostnames: list[str] = []
    for record in resolved_records:
        if not isinstance(record, dict):
            continue
        name = record.get("host") or record.get("hostname") or record.get("name")
        if name:
            hostnames.append(str(name))

    if not hostnames:
        ctx.results["live_hosts"] = []
        return []

    tools = ctx.registry.get("04_http_probing", [])
    if not tools:
        logger.warning("No tools configured for stage 04_http_probing")
        ctx.results["live_hosts"] = []
        return []

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
        for hostname in sorted(set(hostnames)):
            handle.write(f"{hostname}\n")
        input_path = Path(handle.name)

    try:
        results = await run_tools_parallel(tools, ctx.target, ctx.output_dir / "stage_04", input_file=input_path, status_map=ctx.tool_statuses)
        live_hosts: list[dict] = []
        for tool in tools:
            result = results.get(tool.name)
            if result is None or not result.raw_output_path or not result.success:
                logger.warning("HTTP probe tool %s failed: %s", tool.name, result.error if result else "no result")
                continue
            try:
                parser_module = importlib.import_module(f"parsers.{tool.output.parser}")
                live_hosts.extend(parser_module.parse(result.raw_output_path))
            except Exception as exc:  # pragma: no cover - keep stage resilient
                logger.warning("HTTP parser failed for %s: %s", tool.name, exc)
        ctx.results["live_hosts"] = live_hosts
        out_path = ctx.output_dir / "live_hosts.json"
        with out_path.open("w", encoding="utf-8") as handle:
            json.dump(live_hosts, handle, indent=2)
        logger.info("Stage 04 complete: %s live hosts", len(live_hosts))
        return live_hosts
    finally:
        input_path.unlink(missing_ok=True)
