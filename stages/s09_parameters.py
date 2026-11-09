from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from core.logger import get_logger
from core.runner import run_tools_parallel

if TYPE_CHECKING:
    from core.engine import ScanContext

logger = get_logger(__name__)


def _ensure_gf_patterns() -> Path:
    """Copy bundled gf patterns into the user's gf directory so the local runtime works offline."""
    repo_root = Path(__file__).resolve().parents[1]
    source_dir = repo_root / "data" / "gf_patterns"
    pattern_dir = Path.home() / ".config" / "gf"
    if not pattern_dir.exists():
        pattern_dir = Path.home() / ".gf"
    pattern_dir.mkdir(parents=True, exist_ok=True)

    for source_path in sorted(source_dir.glob("*.json")):
        target_path = pattern_dir / source_path.name
        if not target_path.exists() or target_path.read_bytes() != source_path.read_bytes():
            shutil.copy2(source_path, target_path)

    os.environ["GF_PATTERNS_DIR"] = str(pattern_dir)
    return pattern_dir


async def run_stage_09(ctx: "ScanContext", urls: list[str]) -> dict:
    """Deduplicate URLs, scan them with gf patterns, and optionally brute-force params with arjun."""
    tools = ctx.registry.get("09_parameters", [])
    if not tools:
        logger.warning("No tools configured for stage 09_parameters")
        findings = {"xss_candidates": [], "sqli_candidates": [], "ssrf_candidates": [], "redirect_candidates": []}
        ctx.results["param_findings"] = findings
        out_path = ctx.output_dir / "param_findings.json"
        with out_path.open("w", encoding="utf-8") as handle:
            json.dump(findings, handle, indent=2)
        return findings

    uro_tool = next((tool for tool in tools if tool.name == "uro"), None)
    gf_tool = next((tool for tool in tools if tool.name == "gf"), None)
    arjun_tool = next((tool for tool in tools if tool.name == "arjun"), None)

    deduped_urls = list(dict.fromkeys(str(url).strip() for url in urls if str(url).strip()))
    if not deduped_urls:
        findings = {"xss_candidates": [], "sqli_candidates": [], "ssrf_candidates": [], "redirect_candidates": []}
        ctx.results["param_findings"] = findings
        out_path = ctx.output_dir / "param_findings.json"
        with out_path.open("w", encoding="utf-8") as handle:
            json.dump(findings, handle, indent=2)
        return findings

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
        for url in deduped_urls:
            handle.write(f"{url}\n")
        input_path = Path(handle.name)
    deduped_input_path: Path | None = None

    try:
        deduped: list[str] = deduped_urls
        if uro_tool is not None:
            results = await run_tools_parallel([uro_tool], ctx.target, ctx.output_dir / "stage_09", input_file=input_path, status_map=ctx.tool_statuses)
            result = results.get(uro_tool.name)
            if result is not None and result.success and result.raw_output_path:
                try:
                    from parsers.plain_lines import parse as parse_plain
                    deduped = parse_plain(result.raw_output_path)
                except Exception as exc:  # pragma: no cover - parser issues should be logged, not fatal
                    logger.warning("uro parser failed: %s", exc)
                    deduped = deduped_urls
            else:
                deduped = deduped_urls

        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
            for url in deduped:
                handle.write(f"{url}\n")
            deduped_input_path = Path(handle.name)

        pattern_dir = _ensure_gf_patterns()
        pattern_files = sorted(pattern_dir.glob("*.json"))
        findings: dict[str, list[str]] = {}
        for pattern_file in pattern_files:
            pattern_name = pattern_file.stem
            if gf_tool is None:
                findings[f"{pattern_name}_candidates"] = []
                continue
            gf_results = await run_tools_parallel(
                [gf_tool],
                ctx.target,
                ctx.output_dir / "stage_09",
                input_file=deduped_input_path,
                status_map=ctx.tool_statuses,
                extra_format_fields={"pattern_name": pattern_name},
            )
            result = gf_results.get(gf_tool.name)
            if result is None or not result.success or not result.raw_output_path:
                logger.warning("gf pattern %s failed: %s", pattern_name, result.error if result else "no result")
                findings[f"{pattern_name}_candidates"] = []
                continue
            try:
                from parsers.plain_lines import parse as parse_plain
                findings[f"{pattern_name}_candidates"] = parse_plain(result.raw_output_path)
            except Exception as exc:  # pragma: no cover - resilient parser handling
                logger.warning("gf parser failed for %s: %s", pattern_name, exc)
                findings[f"{pattern_name}_candidates"] = []

        discovered_params: list[dict] = []
        if ctx.scope.allow_active_scans and arjun_tool is not None:
            arjun_urls = deduped[:50]
            if len(deduped) > 50:
                logger.info("Stage 09 arjun cap: skipped %s URLs after the first 50", len(deduped) - 50)
            with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
                for url in arjun_urls:
                    handle.write(f"{url}\n")
                arjun_input = Path(handle.name)
            try:
                arjun_results = await run_tools_parallel([arjun_tool], ctx.target, ctx.output_dir / "stage_09", input_file=arjun_input, status_map=ctx.tool_statuses)
                result = arjun_results.get(arjun_tool.name)
                if result is not None and result.success and result.raw_output_path:
                    try:
                        from parsers.jsonl import parse as parse_jsonl
                        discovered_params = parse_jsonl(result.raw_output_path)
                    except Exception as exc:  # pragma: no cover
                        logger.warning("arjun parser failed: %s", exc)
            finally:
                arjun_input.unlink(missing_ok=True)
        elif arjun_tool is not None:
            logger.info("stage 09: arjun skipped — active scans not enabled in scope config")

        if discovered_params:
            findings["discovered_params"] = discovered_params

        ctx.results["param_findings"] = findings
        out_path = ctx.output_dir / "param_findings.json"
        with out_path.open("w", encoding="utf-8") as handle:
            json.dump(findings, handle, indent=2)
        logger.info("Stage 09 complete: %s parameter findings", sum(len(items) for items in findings.values() if isinstance(items, list)))
        return findings
    finally:
        input_path.unlink(missing_ok=True)
        if deduped_input_path is not None:
            deduped_input_path.unlink(missing_ok=True)
