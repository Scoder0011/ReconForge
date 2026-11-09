from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit, urlunsplit

import yaml

from core.logger import get_logger
from core.runner import run_tools_parallel
from core.scope import ScopeConfig, is_in_scope

if TYPE_CHECKING:
    from core.engine import ScanContext

logger = get_logger(__name__)

_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


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


def _validated_target_url(value: object, scope: ScopeConfig) -> str | None:
    """Return a normalized HTTP URL only when its valid hostname is in scope."""
    url = str(value or "").strip()
    if not url or any(ord(char) <= 32 or ord(char) == 127 for char in url):
        logger.info("Dropped malformed content-discovery target URL")
        return None

    try:
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError:
        logger.info("Dropped malformed content-discovery target URL: %s", url)
        return None

    labels = hostname.split(".")
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or parsed.username is not None
        or parsed.password is not None
        or len(hostname) > 253
        or len(labels) < 2
        or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels)
        or (port is not None and not 1 <= port <= 65535)
    ):
        logger.info("Dropped malformed content-discovery target URL: %s", url)
        return None

    if not is_in_scope(hostname, scope):
        logger.info("Dropped content-discovery target outside configured scope: %s", url)
        return None

    netloc = hostname if port is None else f"{hostname}:{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path.rstrip("/"), "", ""))


async def run_stage_10(ctx: "ScanContext", live_hosts: list[dict]) -> list[dict]:
    """Discover paths on a bounded set of valid, authorized live hosts."""
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
            validated_url = _validated_target_url(url, ctx.scope)
            if validated_url and validated_url not in targets:
                targets.append(validated_url)

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
    if not wordlist_path.is_file():
        logger.error("Stage 10 wordlist does not exist or is not a file: %s", wordlist_path)
        ctx.results["content_discovery"] = []
        out_path = ctx.output_dir / "content_discovery.json"
        with out_path.open("w", encoding="utf-8") as handle:
            json.dump([], handle, indent=2)
        return []

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
