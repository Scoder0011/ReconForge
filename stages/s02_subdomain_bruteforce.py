from __future__ import annotations

import importlib
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from core.logger import get_logger
from core.runner import run_tools_parallel
from core.scope import filter_in_scope

if TYPE_CHECKING:
    from core.engine import ScanContext

logger = get_logger(__name__)


async def run_stage_02(ctx: "ScanContext", known_hostnames: list[str]) -> list[str]:
    """Generate permutation candidates from known hostnames when active scans are explicitly enabled."""
    if not ctx.scope.allow_active_scans:
        logger.info("stage 02 skipped: active scans not enabled in scope config")
        return list(dict.fromkeys(known_hostnames))

    tools = ctx.registry.get("02_subdomain_bruteforce", [])
    if not tools:
        logger.warning("No tools configured for stage 02_subdomain_bruteforce")
        return list(dict.fromkeys(known_hostnames))

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
        for hostname in known_hostnames:
            handle.write(f"{hostname}\n")
        input_path = Path(handle.name)

    try:
        results = await run_tools_parallel(tools, ctx.target, ctx.output_dir / "stage_02", input_file=input_path, status_map=ctx.tool_statuses)
        generated: list[str] = []
        for tool in tools:
            result = results.get(tool.name)
            if result is None or not result.raw_output_path or not result.success:
                logger.warning("Permutation tool %s failed: %s", tool.name, result.error if result else "no result")
                continue
            try:
                parser_module = importlib.import_module(f"parsers.{tool.output.parser}")
                generated.extend(parser_module.parse(result.raw_output_path))
            except Exception as exc:  # pragma: no cover - keep stage resilient
                logger.warning("Permutation parser failed for %s: %s", tool.name, exc)
        max_generated_candidates = 10000
        if len(generated) > max_generated_candidates:
            logger.warning(
                "Stage 02 generated %s permutation hostnames; trimming generated additions to %s",
                len(generated),
                max_generated_candidates,
            )
            generated = generated[:max_generated_candidates]
        combined = list(dict.fromkeys(known_hostnames + generated))
        kept, dropped = filter_in_scope(combined, ctx.scope)
        ctx.results["permutations"] = kept
        logger.info("Stage 02 complete: %s candidate hostnames, %s dropped", len(kept), len(dropped))
        return kept
    finally:
        input_path.unlink(missing_ok=True)
