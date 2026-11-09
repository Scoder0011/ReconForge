from __future__ import annotations

import importlib
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from core.logger import get_logger
from core.runner import run_tools_parallel

if TYPE_CHECKING:
    from core.engine import ScanContext

logger = get_logger(__name__)


async def run_stage_06(ctx: "ScanContext", live_hosts: list[dict]) -> list[dict]:
    """Capture screenshots for each confirmed live host and persist the structured results."""
    urls = []
    for host in live_hosts:
        if not isinstance(host, dict):
            continue
        url = host.get("url") or host.get("URL")
        if url:
            urls.append(str(url))

    if not urls:
        ctx.results["screenshots"] = []
        return []

    browser_names = [
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
        "google-chrome-beta",
        "google-chrome-unstable",
    ]
    browser_path = next((name for name in browser_names if shutil.which(name)), None)
    if browser_path is None:
        logger.warning(
            "Stage 06: no Chrome/Chromium browser detected. gowitness requires a headless browser; install Chromium/Chrome and retry. Screenshots will be skipped."
        )
        ctx.results["screenshots"] = []
        return []

    tools = ctx.registry.get("06_screenshots", [])
    if not tools:
        logger.warning("No tools configured for stage 06_screenshots")
        ctx.results["screenshots"] = []
        return []

    screenshot_dir = ctx.output_dir / "screenshots"
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
        for url in sorted(set(urls)):
            handle.write(f"{url}\n")
        input_path = Path(handle.name)

    try:
        results = await run_tools_parallel(
            tools,
            ctx.target,
            ctx.output_dir / "stage_06",
            input_file=input_path,
            status_map=ctx.tool_statuses,
            extra_format_fields={"screenshot_dir": str(screenshot_dir)},
        )
        screenshots: list[dict] = []
        for tool in tools:
            result = results.get(tool.name)
            if result is None or not result.success:
                logger.warning("Screenshot tool %s failed: %s", tool.name, result.error if result else "no result")
                continue
            if not tool.output:
                continue
            try:
                parser_module = importlib.import_module(f"parsers.{tool.output.parser}")
                parsed = parser_module.parse(ctx.output_dir / "stage_06" / f"{tool.name}.raw.db")
                if not parsed:
                    fallback = ctx.output_dir / "stage_06" / f"{tool.name}.raw.jsonl"
                    if fallback.exists():
                        parsed = parser_module.parse(fallback)
                screenshots.extend(parsed)
            except Exception as exc:  # pragma: no cover - keep stage resilient
                logger.warning("Screenshot parser failed for %s: %s", tool.name, exc)

        if not screenshots:
            logger.warning(
                "Stage 06: no screenshots were produced. This usually means the browser runtime is unavailable or gowitness could not render the page. Check that Chrome/Chromium is installed and reachable on PATH."
            )

        deduped: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for item in screenshots:
            url = str(item.get("url") or "").strip()
            screenshot_path = str(item.get("screenshot_path") or "").strip()
            key = (url, screenshot_path)
            if not url or key in seen:
                continue
            seen.add(key)
            deduped.append(item)

        ctx.results["screenshots"] = deduped
        out_path = ctx.output_dir / "screenshots.json"
        with out_path.open("w", encoding="utf-8") as handle:
            import json
            json.dump(deduped, handle, indent=2)
        logger.info("Stage 06 complete: %s screenshots", len(deduped))
        return deduped
    finally:
        input_path.unlink(missing_ok=True)
