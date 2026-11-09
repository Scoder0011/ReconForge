from __future__ import annotations

import importlib
import json
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from core.logger import get_logger
from core.runner import run_tool, run_tools_parallel

if TYPE_CHECKING:
    from core.engine import ScanContext

logger = get_logger(__name__)


def _collect_ips_and_hosts(resolved_records: list[dict]) -> tuple[list[str], list[str]]:
    """Collect hostname and IP inputs from DNS resolution output."""
    hostnames: list[str] = []
    ips: list[str] = []
    for record in resolved_records:
        if not isinstance(record, dict):
            continue
        host = str(record.get("host") or record.get("hostname") or record.get("name") or "").strip()
        if host:
            hostnames.append(host)

        values: list[str] = []
        a_value = record.get("a")
        if isinstance(a_value, list):
            values.extend(str(item) for item in a_value)
        elif isinstance(a_value, str):
            values.append(a_value)
        if not values:
            ip_value = record.get("ip")
            if isinstance(ip_value, str):
                values.append(ip_value)
            elif isinstance(ip_value, list):
                values.extend(str(item) for item in ip_value)
        for value in values:
            cleaned = str(value).strip()
            if cleaned:
                ips.append(cleaned)
    return sorted(set(hostnames)), sorted(set(ips))


async def run_stage_05(ctx: "ScanContext", resolved_records: list[dict]) -> dict:
    """Collect TLS certificate metadata and, when authorized, run port scanning on live IPs."""
    hostnames, ips = _collect_ips_and_hosts(resolved_records)
    tools = ctx.registry.get("05_ports_infra", [])
    tls_tool = next((tool for tool in tools if tool.name == "tlsx"), None)

    tls_results: list[dict] = []
    if tls_tool is not None:
        if not hostnames:
            tls_results = []
        else:
            with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
                for hostname in hostnames:
                    handle.write(f"{hostname}\n")
                input_path = Path(handle.name)
            try:
                results = await run_tools_parallel([tls_tool], ctx.target, ctx.output_dir / "stage_05", input_file=input_path, status_map=ctx.tool_statuses)
                result = results.get(tls_tool.name)
                if result is None or not result.raw_output_path or not result.success:
                    logger.warning("tlsx failed: %s", result.error if result else "no result")
                else:
                    try:
                        parser_module = importlib.import_module(f"parsers.{tls_tool.output.parser}")
                        tls_results = parser_module.parse(result.raw_output_path)
                    except Exception as exc:  # pragma: no cover - resilient parser handling
                        logger.warning("tlsx parser failed: %s", exc)
            finally:
                input_path.unlink(missing_ok=True)
    else:
        logger.warning("No tlsx tool configured for stage 05_ports_infra")

    result_payload = {"tls": tls_results, "ports": []}
    if not ctx.scope.allow_active_scans:
        logger.info("stage 05: naabu skipped — active scans not enabled in scope config")
        logger.info("stage 05: nmap skipped — active scans not enabled in scope config")
        ctx.results["tls"] = tls_results
        ctx.results["ports"] = []
        ctx.results["ports_and_tls"] = result_payload
        output_path = ctx.output_dir / "ports_and_tls.json"
        output_path.write_text(json.dumps(result_payload, indent=2), encoding="utf-8")
        logger.info("Stage 05 complete: %s TLS certs, %s port reports", len(tls_results), 0)
        return result_payload

    naabu_tool = next((tool for tool in tools if tool.name == "naabu"), None)
    nmap_tool = next((tool for tool in tools if tool.name == "nmap"), None)
    all_port_records: list[dict] = []
    port_entries: list[dict] = []

    if naabu_tool is not None and ips:
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
            for ip_value in ips:
                handle.write(f"{ip_value}\n")
            input_path = Path(handle.name)
        try:
            results = await run_tools_parallel([naabu_tool], ctx.target, ctx.output_dir / "stage_05", input_file=input_path, status_map=ctx.tool_statuses)
            result = results.get(naabu_tool.name)
            if result is None or not result.raw_output_path or not result.success:
                logger.warning("naabu failed: %s", result.error if result else "no result")
            else:
                try:
                    parser_module = importlib.import_module(f"parsers.{naabu_tool.output.parser}")
                    port_entries = parser_module.parse(result.raw_output_path)
                except Exception as exc:  # pragma: no cover - resilient parser handling
                    logger.warning("naabu parser failed: %s", exc)
                    port_entries = []
        finally:
            input_path.unlink(missing_ok=True)

        open_ports_by_ip: dict[str, set[int]] = {}
        for entry in port_entries:
            if not isinstance(entry, dict):
                continue
            ip_value = str(entry.get("ip") or entry.get("host") or entry.get("hostname") or "").strip()
            port_value = entry.get("port")
            if not ip_value:
                continue
            try:
                port_number = int(port_value)
            except (TypeError, ValueError):
                if isinstance(port_value, dict):
                    port_number = int(port_value.get("port") or 0)
                else:
                    continue
            if port_number <= 0:
                continue
            open_ports_by_ip.setdefault(ip_value, set()).add(port_number)

        if nmap_tool is not None and open_ports_by_ip:
            nmap_cap = 20
            limited = list(open_ports_by_ip.items())[:nmap_cap]
            skipped_count = max(0, len(open_ports_by_ip) - len(limited))
            if skipped_count:
                logger.info("stage 05: nmap skipped %s IPs due to cap (first %s analyzed)", skipped_count, len(limited))
            for ip_value, ports in limited:
                port_list = ",".join(str(port) for port in sorted(ports))
                ip_dir = ctx.output_dir / "stage_05" / f"nmap_{ip_value.replace('.', '_')}"
                ip_dir.mkdir(parents=True, exist_ok=True)
                status = ctx.tool_statuses.get(nmap_tool.name)
                result = await run_tool(
                    nmap_tool,
                    ctx.target,
                    ip_dir,
                    input_file=None,
                    status=status,
                    extra_format_fields={"target_ip": ip_value, "port_list": port_list},
                )
                if result is None or not result.raw_output_path or not result.success:
                    logger.warning("nmap failed for %s: %s", ip_value, result.error if result else "no result")
                    continue
                try:
                    parser_module = importlib.import_module(f"parsers.{nmap_tool.output.parser}")
                    parsed = parser_module.parse(result.raw_output_path)
                    all_port_records.extend(parsed)
                except Exception as exc:  # pragma: no cover - resilient parser handling
                    logger.warning("nmap parser failed for %s: %s", ip_value, exc)

    deduped: list[dict] = []
    seen: set[tuple[str, tuple[tuple[int, str, str, str], ...]]] = set()
    for record in all_port_records:
        if not isinstance(record, dict):
            continue
        ip_value = str(record.get("ip") or "").strip()
        ports = record.get("ports") or []
        if not ip_value:
            continue
        key_ports = []
        for port in ports:
            if not isinstance(port, dict):
                continue
            key_ports.append(
                (
                    int(port.get("port") or 0),
                    str(port.get("protocol") or ""),
                    str(port.get("service") or ""),
                    str(port.get("product") or ""),
                )
            )
        key = (ip_value, tuple(sorted(key_ports)))
        if key in seen:
            continue
        seen.add(key)
        deduped.append({"ip": ip_value, "ports": ports})

    result_payload = {"tls": tls_results, "ports": deduped}
    ctx.results["tls"] = tls_results
    ctx.results["ports"] = deduped
    ctx.results["ports_and_tls"] = result_payload
    output_path = ctx.output_dir / "ports_and_tls.json"
    output_path.write_text(json.dumps(result_payload, indent=2), encoding="utf-8")
    logger.info("Stage 05 complete: %s TLS certs, %s port records", len(tls_results), len(deduped))
    return result_payload
