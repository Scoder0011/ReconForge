from __future__ import annotations

import importlib
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from core.logger import get_logger
from core.runner import run_tools_parallel
from core.scope import is_in_scope

try:
    from typing import TYPE_CHECKING
except Exception:  # pragma: no cover - compatibility fallback
    TYPE_CHECKING = False

if TYPE_CHECKING:
    from core.engine import ScanContext

logger = get_logger(__name__)


async def run_stage_07(ctx: "ScanContext", live_hosts: list[dict]) -> list[str]:
    """Collect historical and crawled URLs while filtering out anything outside scope."""
    tools = ctx.registry.get("07_url_collection", [])
    if not tools:
        logger.warning("No tools configured for stage 07_url_collection")
        ctx.results["urls"] = []
        return []

    gau_tool = next((tool for tool in tools if tool.name == "gau"), None)
    katana_tool = next((tool for tool in tools if tool.name == "katana"), None)

    collected: list[str] = []

    if gau_tool is not None:
        results = await run_tools_parallel([gau_tool], ctx.target, ctx.output_dir / "stage_07", status_map=ctx.tool_statuses)
        result = results.get(gau_tool.name)
        if result is None or not result.raw_output_path or not result.success:
            logger.warning("gau failed: %s", result.error if result else "no result")
        else:
            try:
                parser_module = importlib.import_module(f"parsers.{gau_tool.output.parser}")
                collected.extend(parser_module.parse(result.raw_output_path))
            except Exception as exc:  # pragma: no cover - resilient parser handling
                logger.warning("gau parser failed: %s", exc)

    if ctx.scope.allow_active_scans and katana_tool is not None:
        live_urls = []
        for host in live_hosts:
            if not isinstance(host, dict):
                continue
            url = host.get("url") or host.get("URL")
            if url:
                live_urls.append(str(url))

        if live_urls:
            with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
                for url in sorted(set(live_urls)):
                    handle.write(f"{url}\n")
                input_path = Path(handle.name)
            try:
                results = await run_tools_parallel([katana_tool], ctx.target, ctx.output_dir / "stage_07", input_file=input_path, status_map=ctx.tool_statuses)
                result = results.get(katana_tool.name)
                if result is None or not result.raw_output_path or not result.success:
                    logger.warning("katana failed: %s", result.error if result else "no result")
                else:
                    try:
                        parser_module = importlib.import_module(f"parsers.{katana_tool.output.parser}")
                        collected.extend(parser_module.parse(result.raw_output_path))
                    except Exception as exc:  # pragma: no cover - resilient parser handling
                        logger.warning("katana parser failed: %s", exc)
            finally:
                input_path.unlink(missing_ok=True)
    elif katana_tool is not None:
        logger.info("stage 07: katana skipped — active scans not enabled in scope config")

    deduped: list[str] = []
    seen: set[str] = set()
    for value in collected:
        url = str(value).strip()
        if not url:
            continue
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host:
            continue
        if not is_in_scope(host, ctx.scope):
            continue
        if url.lower() in seen:
            continue
        seen.add(url.lower())
        deduped.append(url)

    ctx.results["urls"] = deduped
    output_path = ctx.output_dir / "urls.txt"
    output_path.write_text("\n".join(deduped) + ("\n" if deduped else ""), encoding="utf-8")
    logger.info("Stage 07 complete: %s in-scope URLs", len(deduped))
    return deduped
