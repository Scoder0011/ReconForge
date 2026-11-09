from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.dependency_check import check_all, detect_os
from core.installer import install_missing
from core.registry import load_stage


def _format_table(rows: list[tuple[str, str, str, str, str]]) -> str:
    headers = ["Tool", "Stage", "Installed", "Version", "Path"]
    widths = [len(header) for header in headers]
    for row in rows:
        widths[0] = max(widths[0], len(row[0]))
        widths[1] = max(widths[1], len(row[1]))
        widths[2] = max(widths[2], len(row[2]))
        widths[3] = max(widths[3], len(row[3]))
        widths[4] = max(widths[4], len(row[4]))

    header_line = "  ".join(header.ljust(widths[idx]) for idx, header in enumerate(headers))
    sep = "  ".join("-" * width for width in widths)
    lines = [header_line, sep]
    for row in rows:
        lines.append("  ".join(value.ljust(widths[idx]) for idx, value in enumerate(row)))
    return "\n".join(lines)


def _summary(os_info) -> str:
    distro_name = os_info.distro_name or ("macOS" if os_info.system == "darwin" else "Linux")
    distro_family = os_info.distro_family or "unknown"
    if os_info.system == "darwin":
        summary = f"Detected: {distro_name} ({distro_family}), Go: {'yes' if os_info.has_go else 'no'}, WSL: {'yes' if os_info.is_wsl else 'no'}"
    else:
        summary = f"Detected: {distro_name} ({distro_family}/{'apt' if os_info.has_apt else 'no-apt'}), Go: {'yes' if os_info.has_go else 'no'}, WSL: {'yes' if os_info.is_wsl else 'no'}"
    return summary


def _load_tools() -> list:
    registry_dir = ROOT / "tools_registry"
    tools: list = []
    for stage_name in ["01_subdomain_passive", "02_subdomain_bruteforce", "03_dns", "04_http_probing"]:
        tools.extend(load_stage(registry_dir, stage_name))
    return tools


def _render_status_table(statuses: dict[str, object], tools: list) -> str:
    rows: list[tuple[str, str, str, str, str, str]] = []
    for tool in tools:
        status = statuses.get(tool.name)
        installed = status.installed if status is not None else False
        version = (status.version or "") if status is not None else ""
        path = (status.path or "") if status is not None else ""
        resolved = getattr(status, "resolved_binary", None) if status is not None else None
        rows.append((tool.name, tool.stage, "✓" if installed else "✗", version[:40], path[:40], resolved or ""))

    headers = ["Tool", "Stage", "Installed", "Version", "Path", "Resolved"]
    widths = [len(header) for header in headers]
    for row in rows:
        for idx, value in enumerate(row):
            widths[idx] = max(widths[idx], len(value))
    lines = ["  ".join(header.ljust(widths[idx]) for idx, header in enumerate(headers))]
    lines.append("  ".join("-" * width for width in widths))
    for row in rows:
        lines.append("  ".join(value.ljust(widths[idx]) for idx, value in enumerate(row)))
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check the local environment for the Phase 1 required recon tools. "
        "Use only on assets you own or are explicitly authorized to assess."
    )
    parser.add_argument("--install", action="store_true", help="Install any missing tools before re-checking.")
    parser.add_argument("--dry-run", action="store_true", help="Preview install commands without running them.")
    args = parser.parse_args()

    try:
        os_info = detect_os()
        print(_summary(os_info))

        tools = _load_tools()
        statuses = check_all(tools)
        print(_render_status_table(statuses, tools))

        if args.install:
            missing_tools = [tool for tool in tools if (tool.binary is not None or tool.binary_candidates) and (statuses.get(tool.name) is None or not statuses[tool.name].installed)]
            results = install_missing(missing_tools, statuses, os_info, dry_run=args.dry_run)
            for result in results:
                print(f"{result.tool_name} ({result.method}): success={result.success} -> {result.output}")
            statuses = check_all(tools)
            print(_render_status_table(statuses, tools))

        missing = [
            tool for tool in tools
            if (tool.binary is not None or tool.binary_candidates) and (statuses.get(tool.name) is None or not statuses[tool.name].installed)
        ]
        if not missing:
            return 0

        print(f"Missing tools: {', '.join(tool.name for tool in missing)}")
        return 1
    except Exception as exc:  # pragma: no cover - safety net for CLI entrypoint
        print(f"Error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
