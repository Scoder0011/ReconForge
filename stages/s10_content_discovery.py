from __future__ import annotations

import json
import yaml
from pathlib import Path
from typing import TYPE_CHECKING

from core.logger import get_logger
from core.runner import run_tools_parallel

if TYPE_CHECKING:
    from core.engine import ScanContext

logger = get_logger(__name__)


def _resolve_wordlist_path() -> Path:
    """Return the configured wordlist path or the bundled offline default."""
    repo_root = Path(__file__).resolve().parents[1]
    config_path = repo_root / "config" / "config.yaml"
    configured = None
    if config_path.exists():
        try:
            with config_path.open("r", encoding="utf-8") as handle:
                config = yaml.safe_load(handle) or {}
            configured = config.get("wordlist_path")
        except Exception:
            configured = None
    if configured:
        candidate = Path(configured)
        if not candidate.is_absolute():
            candidate = repo_root / candidate
        if candidate.exists():
            return candidate
    default_path = repo_root / "data" / "wordlists" / "common-small.txt"
    if default_path.exists():
        return default_path
    return repo_root / "data" / "wordlists" / "common-small.txt"


async def run_stage_10(ctx: "ScanContext", live_hosts: list[dict]) -> list[dict]:
    """Brute-force common paths/files against a small host sample when active scanning is enabled."""
    if not ctx.scope.allow_active_scans:
        logger.info("stage 10 skipped: active scans not enabled in scope config")
        ctx.results["content_discovery"] = []
        out_path = ctx.output_dir / "content_discovery.json"
        with out_path.open("w", encoding="utf-8") as handle:
            json.dump([], handle, indent=2)
        return []

    targets: list[str] = []
    for host in live_hosts:
        if not isinstance(host, dict):
            continue
        url = host.get("url") or host.get("URL")
        if url:
            targets.append(str(url).strip())

    if not targets:
        ctx.results["content_discovery"] = []
        out_path = ctx.output_dir / "content_discovery.json"
        with out_path.open("w", encoding="utf-8") as handle:
            json.dump([], handle, indent=2)
        return []

    if len(targets) > 10:
        logger.info("Stage 10 content discovery cap: skipped %s hosts after the first 10", len(targets) - 10)
    sample_targets = targets[:10]

    tools = ctx.registry.get("10_content_discovery", [])
    if not tools:
        logger.warning("No tools configured for stage 10_content_discovery")
        ctx.results["content_discovery"] = []
        out_path = ctx.output_dir / "content_discovery.json"
        with out_path.open("w", encoding="utf-8") as handle:
            json.dump([], handle, indent=2)
        return []

    wordlist_path = _resolve_wordlist_path()
    findings: list[dict] = []
    for target_url in sample_targets:
        results = await run_tools_parallel(
            tools,
            ctx.target,
            ctx.output_dir / "stage_10",
            status_map=ctx.tool_statuses,
            extra_format_fields={"target_url": target_url, "wordlist_path": str(wordlist_path)},
        )
        for tool in tools:
            result = results.get(tool.name)
            if result is None or not result.success or not result.raw_output_path:
                logger.warning("Content discovery tool %s failed for %s: %s", tool.name, target_url, result.error if result else "no result")
                continue
            try:
                parser_module = __import__(f"parsers.{tool.output.parser}", fromlist=["parse"])
                parsed = parser_module.parse(result.raw_output_path)
            except Exception as exc:  # pragma: no cover - resilient parser handling
                logger.warning("Content discovery parser failed for %s: %s", tool.name, exc)
                continue
            for item in parsed:
                if not isinstance(item, dict):
                    continue
                entry = dict(item)
                url = str(entry.get("url") or entry.get("URL") or "").strip()
                if not url:
                    continue
                if any(existing.get("url") == url for existing in findings):
                    continue
                findings.append(entry)

    ctx.results["content_discovery"] = findings
    out_path = ctx.output_dir / "content_discovery.json"
    with out_path.open("w", encoding="utf-8") as handle:
        json.dump(findings, handle, indent=2)
    logger.info("Stage 10 complete: %s discovered content entries", len(findings))
    return findings
