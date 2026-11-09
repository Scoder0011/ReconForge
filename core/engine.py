from __future__ import annotations

import asyncio
import importlib
import json
import tempfile
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.dependency_check import check_all
from core.dedupe import dedupe_hostnames
from core.logger import get_logger
from core.registry import ToolSpec, load_all
from core.runner import run_tools_parallel
from core.scope import ScopeConfig, ScopeViolation, filter_in_scope, load_scope
from stages.s02_subdomain_bruteforce import run_stage_02
from stages.s04_http_probing import run_stage_04
from stages.s05_ports_infra import run_stage_05
from stages.s06_screenshots import run_stage_06
from stages.s07_url_collection import run_stage_07
from stages.s08_javascript import run_stage_08
from stages.s09_parameters import run_stage_09
from stages.s10_content_discovery import run_stage_10
from stages.s11_vuln_checks import run_stage_11
from stages.s12_cloud_secrets import run_stage_12

logger = get_logger(__name__)


@dataclass
class ScanContext:
    """Mutable state for a scan run across multiple stages."""

    target: str
    scope: ScopeConfig
    output_dir: Path
    registry: dict[str, list[ToolSpec]]
    tool_statuses: dict[str, object] = field(default_factory=dict)
    results: dict = field(default_factory=dict)


async def run_stage_01_subdomain_passive(ctx: ScanContext) -> list[str]:
    """Run passive subdomain tools, merge their results, and keep only in-scope hosts."""
    tools = ctx.registry.get("01_subdomain_passive", [])
    if not tools:
        logger.warning("No tools configured for stage 01_subdomain_passive")
        return []

    results = await run_tools_parallel(tools, ctx.target, ctx.output_dir / "stage_01", status_map=ctx.tool_statuses)
    parsed_lists: list[list[str]] = []
    tool_names: list[str] = []

    for tool in tools:
        result = results.get(tool.name)
        if result is None or not result.raw_output_path or not result.success:
            logger.warning("Tool %s failed or produced no output: %s", tool.name, result.error if result else "no result")
            continue
        try:
            parser_module = importlib.import_module(f"parsers.{tool.output.parser}")
            parsed = parser_module.parse(result.raw_output_path)
        except Exception as exc:  # pragma: no cover - parser issues should be logged, not fatal
            logger.warning("Parser %s failed for %s: %s", tool.output.parser, tool.name, exc)
            continue
        parsed_lists.append(list(parsed))
        tool_names.append(tool.name)

    source_map = dedupe_hostnames(parsed_lists, tool_names)
    stage_hosts = sorted(set(source_map) | {ctx.target.lower()})
    kept, dropped = filter_in_scope(stage_hosts, ctx.scope)

    ctx.results["subdomain_sources"] = source_map
    ctx.results["subdomains"] = kept
    output_path = ctx.output_dir / "subdomains.txt"
    output_path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
    logger.info("Stage 01 complete: %s in-scope subdomains, %s dropped", len(kept), len(dropped))
    return kept


async def run_stage_03_dns(ctx: ScanContext, hostnames: list[str]) -> list[dict]:
    """Resolve hostnames with DNS tools and keep only actual successful resolutions."""
    tools = ctx.registry.get("03_dns", [])
    if not tools:
        logger.warning("No tools configured for stage 03_dns")
        return []

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
        for hostname in hostnames:
            handle.write(f"{hostname}\n")
        input_path = Path(handle.name)

    try:
        run_results = await run_tools_parallel(tools, ctx.target, ctx.output_dir / "stage_03", input_file=input_path, status_map=ctx.tool_statuses)
        records: list[dict] = []
        for tool in tools:
            result = run_results.get(tool.name)
            if result is None or not result.raw_output_path or not result.success:
                logger.warning("DNS tool %s failed: %s", tool.name, result.error if result else "no result")
                continue
            if tool.output.parser != "jsonl":
                continue
            try:
                parser_module = importlib.import_module(f"parsers.{tool.output.parser}")
                records.extend(parser_module.parse(result.raw_output_path))
            except Exception as exc:  # pragma: no cover - stage remains resilient to parser issues
                logger.warning("DNS parser failed for %s: %s", tool.name, exc)

        resolved_records: list[dict] = []
        seen_hosts: set[str] = set()
        for record in records:
            if not isinstance(record, dict):
                continue
            host = str(record.get("host") or record.get("hostname") or record.get("name") or "").strip().lower()
            if not host:
                continue
            status = str(record.get("status_code") or "").upper()
            if status and status != "NOERROR":
                continue
            if host in seen_hosts:
                continue
            seen_hosts.add(host)
            resolved_records.append(record)

        ctx.results["dns_records"] = resolved_records
        dns_path = ctx.output_dir / "dns_records.json"
        with dns_path.open("w", encoding="utf-8") as handle:
            json.dump(resolved_records, handle, indent=2)
        logger.info("Stage 03 complete: %s resolved DNS records", len(resolved_records))
        return resolved_records
    finally:
        if input_path.exists():
            input_path.unlink(missing_ok=True)


async def run_pipeline(
    target: str,
    output_dir: Path,
    registry_dir: Path,
    scope_file: Path | None = None,
    git_repo: str | None = None,
    progress_callback: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
) -> ScanContext:
    """Run the ReconForge pipeline from passive discovery through URL and JS analysis."""
    pipeline_started = time.monotonic()
    output_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Starting ReconForge pipeline for '%s'", target)

    ctx = ScanContext(
        target=target,
        scope=load_scope(target, scope_file),
        output_dir=output_dir,
        registry=load_all(registry_dir),
    )
    stage_tool_names = [
        "01_subdomain_passive",
        "02_subdomain_bruteforce",
        "03_dns",
        "04_http_probing",
        "05_ports_infra",
        "06_screenshots",
        "07_url_collection",
        "08_javascript",
        "09_parameters",
        "10_content_discovery",
    ]
    all_tools = [tool for stage_name in stage_tool_names for tool in ctx.registry.get(stage_name, [])]
    ctx.tool_statuses = check_all(all_tools)

    async def publish(event: dict[str, Any]) -> None:
        if progress_callback is not None:
            await progress_callback(event)

    try:
        await publish({"stage": "pipeline", "status": "started", "counts": {}})
        subdomains = await run_stage_01_subdomain_passive(ctx)
        logger.info("Found %s in-scope subdomains", len(subdomains))
        await publish({"stage": "01_subdomain_passive", "status": "complete", "counts": {"subdomains": len(subdomains)}})

        combined = await run_stage_02(ctx, subdomains)
        logger.info("Stage 02 produced %s candidate hostnames", len(combined))
        if not ctx.scope.allow_active_scans:
            await publish({"stage": "02_subdomain_bruteforce", "status": "skipped", "reason": "active scans not enabled in scope config"})
        else:
            await publish({"stage": "02_subdomain_bruteforce", "status": "complete", "counts": {"candidates": len(combined)}})

        dns_records = await run_stage_03_dns(ctx, combined)
        logger.info("Resolved %s DNS records", len(dns_records))
        await publish({"stage": "03_dns", "status": "complete", "counts": {"resolved": len(dns_records)}})

        live_hosts_task = asyncio.create_task(run_stage_04(ctx, dns_records))
        ports_task = asyncio.create_task(run_stage_05(ctx, dns_records))
        live_hosts, ports_and_tls = await asyncio.gather(live_hosts_task, ports_task)
        logger.info("Found %s live hosts", len(live_hosts))
        logger.info(
            "Stage 05 produced %s port records and %s TLS certs",
            len(ports_and_tls.get("ports", [])),
            len(ports_and_tls.get("tls", [])),
        )
        await publish({"stage": "04_http_probing", "status": "complete", "counts": {"live_hosts": len(live_hosts)}})
        if not ctx.scope.allow_active_scans:
            await publish({"stage": "05_ports_infra:naabu+nmap", "status": "skipped", "reason": "active scans not enabled in scope config"})
        await publish({"stage": "05_ports_infra", "status": "complete", "counts": {"port_records": len(ports_and_tls.get("ports", [])), "tls": len(ports_and_tls.get("tls", []))}})

        screenshots_task = asyncio.create_task(run_stage_06(ctx, live_hosts))
        urls_task = asyncio.create_task(run_stage_07(ctx, live_hosts))
        screenshots, urls = await asyncio.gather(screenshots_task, urls_task)
        logger.info("Stage 06 produced %s screenshots and stage 07 produced %s URLs", len(screenshots), len(urls))
        await publish({"stage": "06_screenshots", "status": "complete", "counts": {"screenshots": len(screenshots)}})
        await publish({"stage": "07_url_collection", "status": "complete", "counts": {"urls": len(urls)}})
        if not ctx.scope.allow_active_scans:
            await publish({"stage": "07_url_collection:katana", "status": "skipped", "reason": "active scans not enabled in scope config"})

        js_findings = await run_stage_08(ctx, urls)
        logger.info("Stage 08 produced %s endpoints and %s secrets", len(js_findings.get("endpoints", [])), len(js_findings.get("secrets", [])))
        await publish({"stage": "08_javascript", "status": "complete", "counts": {"endpoints": len(js_findings.get("endpoints", [])), "secrets": len(js_findings.get("secrets", []))}})

        param_task = asyncio.create_task(run_stage_09(ctx, urls))
        content_task = asyncio.create_task(run_stage_10(ctx, live_hosts))
        param_findings, content_findings = await asyncio.gather(param_task, content_task)
        logger.info(
            "Stage 09 produced %s parameter findings and stage 10 produced %s content entries",
            sum(len(items) for items in param_findings.values() if isinstance(items, list)),
            len(content_findings),
        )
        await publish({"stage": "09_parameters", "status": "complete", "counts": {"findings": sum(len(items) for items in param_findings.values() if isinstance(items, list))}})
        if not ctx.scope.allow_active_scans:
            await publish({"stage": "09_parameters:arjun", "status": "skipped", "reason": "active scans not enabled in scope config"})
        if not ctx.scope.allow_active_scans:
            await publish({"stage": "10_content_discovery", "status": "skipped", "reason": "active scans not enabled in scope config"})
        else:
            await publish({"stage": "10_content_discovery", "status": "complete", "counts": {"findings": len(content_findings)}})

        vuln_findings = await run_stage_11(ctx, live_hosts, urls)
        logger.info("Stage 11 status: %s", vuln_findings.get("status", "unknown"))
        await publish({"stage": "11_vuln_checks", "status": "skipped" if vuln_findings.get("status") in {"skipped", "not_configured"} else "complete", "reason": vuln_findings.get("reason", "")})

        cloud_and_secrets = await run_stage_12(ctx, target, git_repo)
        logger.info(
            "Stage 12 completed: %s local repository findings; cloud enumeration %s",
            len(cloud_and_secrets.get("git_secrets", [])),
            cloud_and_secrets.get("status", {}).get("cloud_enum", "unknown"),
        )
        await publish({"stage": "12_cloud_secrets", "status": "complete", "counts": {"git_findings": len(cloud_and_secrets.get("git_secrets", []))}})

        await publish({"stage": "pipeline", "status": "finished", "counts": {"stages_completed": 12}})
        return ctx
    except ScopeViolation as exc:
        logger.error("Scope violation: %s", exc)
        return ctx
    except Exception as exc:
        logger.error("Pipeline failed: %s", exc)
        ctx.results["pipeline_error"] = str(exc)
        await publish({"stage": "pipeline", "status": "failed", "reason": str(exc)})
        return ctx
    finally:
        ctx.results["scan_duration_seconds"] = time.monotonic() - pipeline_started
