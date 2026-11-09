from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
from pathlib import Path
from typing import TYPE_CHECKING

import aiohttp

from core.logger import get_logger
from core.runner import run_tools_parallel

if TYPE_CHECKING:
    from core.engine import ScanContext

logger = get_logger(__name__)


def _dedupe_strings(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        value = str(item).strip()
        if not value:
            continue
        if value.lower() in seen:
            continue
        seen.add(value.lower())
        ordered.append(value)
    return ordered


async def _download_js_file(js_url: str, output_dir: Path) -> Path | None:
    """Download a JS file to a hash-named location and return the local path."""
    encoded = hashlib.sha256(js_url.encode("utf-8")).hexdigest()[:16]
    dest = output_dir / f"{encoded}.js"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(js_url, timeout=aiohttp.ClientTimeout(total=20)) as response:
                response.raise_for_status()
                payload = await response.read()
        dest.write_bytes(payload)
        return dest
    except Exception as exc:  # pragma: no cover - network errors should be logged and skipped
        logger.warning("Failed to download JS file %s: %s", js_url, exc)
        return None


async def _run_jsluice(mode: str, js_path: Path) -> list[str]:
    """Run jsluice in either urls or secrets mode and return the discovered entries."""
    proc = await asyncio.create_subprocess_exec(
        "jsluice",
        mode,
        str(js_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        if stderr:
            logger.warning("jsluice %s on %s failed: %s", mode, js_path, stderr.decode("utf-8", errors="replace").strip())
        return []

    results: list[str] = []
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        cleaned = line.strip()
        if not cleaned:
            continue
        results.append(cleaned)
    return results


async def run_stage_08(ctx: "ScanContext", urls: list[str]) -> dict:
    """Find JavaScript endpoints and secrets by downloading JS files discovered from the live URL set."""
    if not urls:
        findings = {"endpoints": [], "secrets": []}
        ctx.results["js_findings"] = findings
        out_path = ctx.output_dir / "js_findings.json"
        with out_path.open("w", encoding="utf-8") as handle:
            json.dump(findings, handle, indent=2)
        return findings

    tools = ctx.registry.get("08_javascript", [])
    js_urls: set[str] = {url for url in urls if str(url).lower().endswith(".js")}

    subjs_tool = next((tool for tool in tools if tool.name == "subjs"), None)
    if subjs_tool is not None:
        with open(ctx.output_dir / "js_urls_input.txt", "w", encoding="utf-8") as handle:
            for url in sorted(set(urls)):
                handle.write(f"{url}\n")
        input_path = ctx.output_dir / "js_urls_input.txt"
        try:
            results = await run_tools_parallel([subjs_tool], ctx.target, ctx.output_dir / "stage_08", input_file=input_path, status_map=ctx.tool_statuses)
            result = results.get(subjs_tool.name)
            if result and result.success and result.raw_output_path:
                try:
                    parser_module = importlib.import_module(f"parsers.{subjs_tool.output.parser}")
                    js_urls.update(parser_module.parse(result.raw_output_path))
                except Exception as exc:  # pragma: no cover - parser failures should be logged, not fatal
                    logger.warning("subjs parser failed: %s", exc)
        finally:
            input_path.unlink(missing_ok=True)

    js_urls = {value for value in js_urls if str(value).strip()}
    js_dir = ctx.output_dir / "js_files"
    js_dir.mkdir(parents=True, exist_ok=True)

    endpoints: list[str] = []
    secrets: list[str] = []
    downloaded_paths: list[Path] = []

    for js_url in sorted(js_urls):
        js_path = await _download_js_file(js_url, js_dir)
        if js_path is None:
            continue
        downloaded_paths.append(js_path)

    for js_file in downloaded_paths:
        js_url_lines = await _run_jsluice("urls", js_file)
        for line in js_url_lines:
            cleaned = line.strip()
            if not cleaned:
                continue
            try:
                payload = json.loads(cleaned)
            except json.JSONDecodeError:
                endpoints.append(cleaned)
                continue
            if isinstance(payload, dict):
                extracted = payload.get("url")
                if extracted:
                    endpoints.append(str(extracted))

        secret_lines = await _run_jsluice("secrets", js_file)
        for line in secret_lines:
            cleaned = line.strip()
            if cleaned:
                secrets.append(cleaned)

    endpoint_list = _dedupe_strings(endpoints)
    secret_list = _dedupe_strings(secrets)

    findings = {"endpoints": endpoint_list, "secrets": secret_list}
    ctx.results["js_findings"] = findings
    out_path = ctx.output_dir / "js_findings.json"
    with out_path.open("w", encoding="utf-8") as handle:
        json.dump(findings, handle, indent=2)
    logger.info("Stage 08 complete: %s JS endpoints, %s secrets", len(endpoint_list), len(secret_list))
    return findings
