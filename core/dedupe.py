from __future__ import annotations


def dedupe_hostnames(hostname_lists: list[list[str]], tool_names: list[str] | None = None) -> dict[str, list[str]]:
    """Aggregate hostnames from multiple tools while tracking which tool surfaced each one."""
    if tool_names is None:
        tool_names = [f"tool_{index}" for index in range(len(hostname_lists))]
    if len(tool_names) != len(hostname_lists):
        raise ValueError("tool_names length must match hostname_lists length")

    seen: dict[str, list[str]] = {}
    for tool_name, values in zip(tool_names, hostname_lists):
        for hostname in values:
            cleaned = str(hostname).strip().lower()
            if not cleaned:
                continue
            seen.setdefault(cleaned, []).append(tool_name)
    return {hostname: sorted(set(tool_list)) for hostname, tool_list in sorted(seen.items())}
