"""CLI entry point for ReconForge.

Responsible use only: this project is intended for authorized security testing on
assets you own or are explicitly authorized to assess. It must never be used for
unauthorized discovery or intrusive testing outside the specified scope.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from core.dependency_check import check_all, detect_os
from core.db import create_scan, record_scan_event, update_scan_status
from core.engine import run_pipeline
from core.installer import install_missing
from core.logger import get_logger
from core.registry import ToolSpec, load_stage
from reporting.generator import generate_report

logger = get_logger(__name__)


def _ensure_go_bin_on_path() -> None:
    """Ensure Go-installed tools are immediately usable in this session after install."""
    try:
        gopath = subprocess.check_output(["go", "env", "GOPATH"], text=True, stderr=subprocess.STDOUT).strip()
    except (FileNotFoundError, subprocess.SubprocessError):
        return

    if not gopath:
        gopath = str(Path.home() / "go")
    go_bin = str(Path(gopath) / "bin")
    path_entries = os.environ.get("PATH", "").split(os.pathsep)
    if go_bin not in path_entries:
        os.environ["PATH"] = f"{go_bin}{os.pathsep}{os.environ.get('PATH', '')}".rstrip(os.pathsep)


def _prompt_install(missing_names: list[str]) -> bool:
    print(f"{len(missing_names)} tools missing: {', '.join(missing_names)}")
    response = input("Install missing tools now? [Y/n] ")
    return response.strip().lower() not in {"n", "no"}


def _install_if_needed(tools: list[ToolSpec], stage_names: list[str]) -> None:
    statuses = check_all(tools)
    missing_tools = []
    for tool in tools:
        if tool.binary is None and not tool.binary_candidates:
            continue
        status = statuses.get(tool.name)
        if status is None or not status.installed:
            missing_tools.append(tool)

    if not missing_tools:
        print("All required tools are already installed.")
        return

    missing_names = [tool.name for tool in missing_tools]
    print(f"{len(missing_names)} tools missing: {', '.join(missing_names)}")

    install_now = False
    auto = False
    # CLI flags override the interactive prompt.
    if auto:
        install_now = True

    do_install = install_now
    if not do_install:
        answer = input("Install missing tools now? [Y/n] ")
        do_install = answer.strip().lower() not in {"n", "no"}

    if not do_install:
        print("Skipping installation and continuing with available tools.")
        return

    os_info = detect_os()
    results = install_missing(missing_tools, statuses, os_info, dry_run=False)
    for result in results:
        if result.error == "manual":
            print(f"{result.tool_name}: manual installation required")
            print(result.output)
            continue
        state = "installed" if result.success else "failed"
        print(f"{result.tool_name}: {state}")
        if result.output:
            print(result.output)

    refreshed = check_all(tools)
    for tool in tools:
        if tool.binary is None and not tool.binary_candidates:
            continue
        status = refreshed.get(tool.name)
        if status is None:
            print(f"{tool.name}: unavailable")
            continue
        state = "installed" if status.installed else "missing"
        version = status.version or "-"
        resolved = getattr(status, "resolved_binary", None) or (tool.binary if tool.binary else tool.binary_candidates[0] if tool.binary_candidates else '-')
        print(f"{tool.name}: {state}, version={version}, path={status.path or '-'} resolved_binary={resolved}")


async def _run_recorded_pipeline(domain: str, output_dir: Path, registry_path: Path, scope_path: Path | None, git_repo: str | None):
    """Run the existing CLI pipeline and persist its history/status locally."""
    scan_id = await create_scan(domain, output_dir)

    async def publish(event: dict) -> None:
        await record_scan_event(scan_id, event)

    try:
        ctx = await run_pipeline(
            domain,
            output_dir,
            registry_path,
            scope_file=scope_path,
            git_repo=git_repo,
            progress_callback=publish,
        )
    except asyncio.CancelledError:
        await publish({"stage": "pipeline", "status": "cancelled", "reason": "interrupted by user"})
        await update_scan_status(scan_id, "cancelled")
        raise
    except Exception:
        await publish({"stage": "pipeline", "status": "failed", "reason": "pipeline terminated with an unexpected error"})
        await update_scan_status(scan_id, "failed")
        raise
    status = "failed" if ctx.results.get("pipeline_error") else "completed"
    await update_scan_status(scan_id, status)
    return scan_id, ctx


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "ReconForge local recon automation tool. Run only against in-scope assets "
            "you own or are explicitly authorized to assess."
        )
    )
    parser.add_argument("-d", "--domain", default=None, help="Target domain to assess.")
    parser.add_argument("--serve", action="store_true", help="Start the localhost-only read-only API server.")
    parser.add_argument("--output-dir", default=None, help="Base output directory for results.")
    parser.add_argument("--scope", default=None, help="Optional path to a YAML scope file.")
    parser.add_argument("--git-repo", default=None, help="Existing local Git repository directory for a local-only secret audit.")
    parser.add_argument("--registry-dir", default="tools_registry", help="Directory containing registry YAML files.")
    parser.add_argument("-y", "--yes", action="store_true", help="Automatically install missing tools without prompting.")
    parser.add_argument("--no-install", action="store_true", help="Skip auto-installation and continue with the tools that are already available.")
    parser.add_argument("--version", action="store_true", help="Show version information.")
    args = parser.parse_args()

    if args.version:
        print("ReconForge 0.1.0")
        return

    if args.serve:
        import uvicorn

        print("ReconForge API: http://127.0.0.1:8000")
        uvicorn.run("web.backend.app:app", host="127.0.0.1", port=8000, reload=False)
        return
    if not args.domain:
        parser.error("-d/--domain is required unless --serve is used")

    output_dir = Path(args.output_dir) if args.output_dir else Path("output") / args.domain / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    default_scope_path = Path("config") / "scope.yaml"
    scope_path = Path(args.scope) if args.scope else (default_scope_path if default_scope_path.exists() else None)
    registry_path = Path(args.registry_dir)

    _ensure_go_bin_on_path()

    preflight_stage_names = [
        "01_subdomain_passive",
        "02_subdomain_bruteforce",
        "03_dns",
        "04_http_probing",
    ]
    tools: list[ToolSpec] = []
    for stage_name in preflight_stage_names:
        tools.extend(load_stage(registry_path, stage_name))

    if not args.no_install:
        statuses = check_all(tools)
        missing_tools = [tool for tool in tools if (tool.binary is not None or tool.binary_candidates) and (statuses.get(tool.name) is None or not statuses[tool.name].installed)]
        if missing_tools:
            print(f"{len(missing_tools)} tools missing: {', '.join(tool.name for tool in missing_tools)}")
            if args.yes:
                install_now = True
            else:
                install_now = input("Install missing tools now? [Y/n] ").strip().lower() not in {"n", "no"}
            if install_now:
                os_info = detect_os()
                results = install_missing(missing_tools, statuses, os_info)
                _ensure_go_bin_on_path()
                for result in results:
                    if result.error == "manual":
                        print(f"{result.tool_name}: manual installation required")
                        print(result.output)
                    else:
                        print(f"{result.tool_name}: {'installed' if result.success else 'failed'}")
                        if result.output:
                            print(result.output)
                refreshed = check_all(tools)
                for tool in tools:
                    if tool.binary is None and not tool.binary_candidates:
                        continue
                    status = refreshed.get(tool.name)
                    if status is None:
                        print(f"{tool.name}: unavailable")
                        continue
                    state = "installed" if status.installed else "missing"
                    resolved = getattr(status, "resolved_binary", None) or (tool.binary if tool.binary else tool.binary_candidates[0] if tool.binary_candidates else '-')
                    print(f"{tool.name}: {state}, version={status.version or '-'} path={status.path or '-'} resolved_binary={resolved}")
            else:
                print("Skipping installation and continuing with available tools.")

    try:
        scan_id, ctx = asyncio.run(_run_recorded_pipeline(args.domain, output_dir, registry_path, scope_path, args.git_repo))
    except KeyboardInterrupt:
        print("Scan interrupted; its history status has been marked cancelled.")
        return
    report_paths = generate_report(ctx)
    subdomains = ctx.results.get("subdomains", [])
    dns_records = ctx.results.get("dns_records", [])
    permutations = ctx.results.get("permutations", [])
    live_hosts = ctx.results.get("live_hosts", [])
    ports = ctx.results.get("ports", [])
    tls = ctx.results.get("tls", [])
    screenshots = ctx.results.get("screenshots", [])
    urls = ctx.results.get("urls", [])
    js_findings = ctx.results.get("js_findings", {})
    param_findings = ctx.results.get("param_findings", {})
    content_discovery = ctx.results.get("content_discovery", [])
    vuln_findings = ctx.results.get("vuln_findings", {})
    cloud_and_secrets = ctx.results.get("cloud_and_secrets", {})
    open_port_count = sum(len(host.get("ports", [])) if isinstance(host, dict) else 0 for host in ports)
    print(
        f"Found {len(subdomains)} subdomains, {len(dns_records)} resolved, "
        f"{len(permutations)} permutations, {len(live_hosts)} live hosts, "
        f"{open_port_count} open ports, {len(tls)} TLS certs checked, "
        f"{len(screenshots)} screenshots, {len(urls)} URLs, "
        f"{len(js_findings.get('endpoints', []))} JS endpoints, "
        f"{len(js_findings.get('secrets', []))} JS secrets, "
        f"{sum(len(items) for items in param_findings.values() if isinstance(items, list))} parameter matches, "
        f"{len(content_discovery)} content-discovery entries, "
        f"vulnerability checks {vuln_findings.get('status', 'not run')}, "
        f"{len(cloud_and_secrets.get('git_secrets', []))} local git secret findings."
    )
    print(f"Subdomains file: {output_dir / 'subdomains.txt'}")
    print(f"DNS records file: {output_dir / 'dns_records.json'}")
    print(f"Live hosts file: {output_dir / 'live_hosts.json'}")
    print(f"Ports file: {output_dir / 'ports_and_tls.json'}")
    print(f"Screenshots file: {output_dir / 'screenshots.json'}")
    print(f"URLs file: {output_dir / 'urls.txt'}")
    print(f"JS findings file: {output_dir / 'js_findings.json'}")
    print(f"Parameter findings file: {output_dir / 'param_findings.json'}")
    print(f"Content discovery file: {output_dir / 'content_discovery.json'}")
    print(f"Vulnerability findings file: {output_dir / 'vuln_findings.json'}")
    print(f"Cloud/secrets file: {output_dir / 'cloud_and_secrets.json'}")
    print(f"Scan ID: {scan_id}")
    print(f"Markdown report: {report_paths['markdown']}")
    print(f"HTML report: {report_paths['html']}")


if __name__ == "__main__":
    main()
