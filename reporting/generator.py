from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.logger import get_logger

logger = get_logger(__name__)
_SECRET_VALUE_KEYS = {
    "secret",
    "token",
    "password",
    "credential",
    "apikey",
    "accesskey",
    "secretaccesskey",
    "raw",
    "rawv2",
    "match",
    "value",
}


def _read_json(path: Path, fallback: Any) -> Any:
    """Load optional stage JSON output, falling back to in-memory results."""
    if not path.exists():
        return fallback
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Could not read report input %s: %s", path, exc)
        return fallback


def _secret_type(item: Any) -> str:
    """Return a descriptive secret detector/type label without exposing its value."""
    if isinstance(item, dict):
        nested = item.get("finding")
        if isinstance(nested, dict):
            return _secret_type(nested)
        for key in ("type", "rule", "detectorName", "detector", "name", "RuleID", "Description"):
            value = item.get(key)
            if value and str(value).strip():
                return str(value).strip()
    if isinstance(item, str):
        return "secret candidate"
    return "unclassified secret candidate"


def _types(items: Any) -> list[str]:
    if not isinstance(items, list):
        return []
    return sorted({_secret_type(item) for item in items})


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _safe_secret_summaries(items: Any) -> list[dict[str, str]]:
    """Produce report-safe secret summaries containing only detector/type names."""
    if not isinstance(items, list):
        return []
    return [{"type": _secret_type(item)} for item in items]


def _relative_screenshot(path_value: Any, output_dir: Path) -> str:
    path = Path(str(path_value or ""))
    if not str(path_value or ""):
        return ""
    try:
        return path.resolve().relative_to(output_dir.resolve()).as_posix()
    except (OSError, ValueError):
        return path.name


def _expiry_info(tls_records: list[Any]) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    records: list[dict[str, Any]] = []
    for item in tls_records:
        if not isinstance(item, dict):
            continue
        expiry_value = item.get("not_after") or item.get("expiry") or item.get("expiration") or item.get("valid_to")
        days_remaining = None
        expiring_soon = False
        if expiry_value:
            try:
                expiry = datetime.fromisoformat(str(expiry_value).replace("Z", "+00:00"))
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
                days_remaining = (expiry - now).days
                expiring_soon = 0 <= days_remaining < 30
            except ValueError:
                pass
        records.append({**item, "days_remaining": days_remaining, "expiring_soon": expiring_soon})
    return records


def _finding_groups(value: Any) -> list[dict[str, Any]]:
    """Group vulnerability records by severity and order critical findings first."""
    findings: list[dict[str, Any]] = []
    if isinstance(value, dict):
        inner = value.get("findings")
        if isinstance(inner, dict):
            for tool, tool_findings in inner.items():
                for finding in _as_list(tool_findings):
                    if isinstance(finding, dict):
                        findings.append({"tool": tool, **finding})
        elif isinstance(inner, list):
            findings.extend(item for item in inner if isinstance(item, dict))
        else:
            for tool, tool_findings in value.items():
                if tool in {"status", "reason"}:
                    continue
                for finding in _as_list(tool_findings):
                    if isinstance(finding, dict):
                        findings.append({"tool": tool, **finding})
    elif isinstance(value, list):
        findings = [item for item in value if isinstance(item, dict)]

    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    for finding in findings:
        severity = str(finding.get("severity") or "unknown").lower()
        finding["severity"] = severity
    findings.sort(key=lambda finding: rank.get(str(finding.get("severity")), 5))
    return findings


def _stage_row(name: str, data: Any, count: int, ran: bool, reason: str = "") -> dict[str, Any]:
    return {
        "name": name,
        "count": count,
        "status": "ran" if ran else "skipped",
        "result": f"ran, found {count}" if ran else f"skipped — {reason or 'no output recorded'}",
    }


def generate_report(ctx: Any) -> dict[str, Path]:
    """Render Markdown and HTML reports from scan output files and in-memory stage results."""
    output_dir: Path = ctx.output_dir
    results: dict[str, Any] = ctx.results
    subdomains = _read_json(output_dir / "subdomains.json", results.get("subdomains", []))
    if not isinstance(subdomains, list):
        subdomains = results.get("subdomains", [])
    dns_records = _read_json(output_dir / "dns_records.json", results.get("dns_records", []))
    live_hosts = _read_json(output_dir / "live_hosts.json", results.get("live_hosts", []))
    screenshots = _read_json(output_dir / "screenshots.json", results.get("screenshots", []))
    urls_file = output_dir / "urls.txt"
    urls = (
        urls_file.read_text(encoding="utf-8", errors="replace").splitlines()
        if urls_file.exists()
        else results.get("urls", [])
    )
    js_findings = _read_json(output_dir / "js_findings.json", results.get("js_findings", {}))
    params = _read_json(output_dir / "param_findings.json", results.get("param_findings", {}))
    content = _read_json(output_dir / "content_discovery.json", results.get("content_discovery", []))
    ports_tls = _read_json(output_dir / "ports_and_tls.json", results.get("ports_and_tls", {}))
    vuln = _read_json(output_dir / "vuln_findings.json", results.get("vuln_findings", {}))
    cloud = _read_json(output_dir / "cloud_and_secrets.json", results.get("cloud_and_secrets", {}))
    osint = _read_json(output_dir / "osint.json", results.get("osint", {}))

    if not isinstance(ports_tls, dict):
        ports_tls = {}
    ports = _as_list(ports_tls.get("ports", results.get("ports", [])))
    tls = _expiry_info(_as_list(ports_tls.get("tls", results.get("tls", []))))
    if not isinstance(js_findings, dict):
        js_findings = {}
    if not isinstance(params, dict):
        params = {}
    if not isinstance(cloud, dict):
        cloud = {}
    if not isinstance(osint, dict):
        osint = {}

    stage_defs = [
        ("01 — Passive subdomains", "subdomains", _as_list(subdomains)),
        ("02 — Permutations", "permutations", _as_list(results.get("permutations"))),
        ("03 — DNS resolution", "dns_records", _as_list(dns_records)),
        ("04 — HTTP probing", "live_hosts", _as_list(live_hosts)),
        ("05 — Ports and TLS", "ports_and_tls", ports + tls),
        ("06 — Screenshots", "screenshots", _as_list(screenshots)),
        ("07 — URL collection", "urls", _as_list(urls)),
        ("08 — JavaScript analysis", "js_findings", _as_list(js_findings.get("endpoints")) + _as_list(js_findings.get("secrets"))),
        ("09 — Parameters", "param_findings", [entry for entries in params.values() if isinstance(entries, list) for entry in entries]),
        ("10 — Content discovery", "content_discovery", _as_list(content)),
        ("11 — Vulnerability checks", "vuln_findings", _finding_groups(vuln)),
        ("12 — Cloud and secrets", "cloud_and_secrets", _as_list(cloud.get("buckets_found")) + _as_list(cloud.get("git_secrets"))),
        ("13 — OSINT", "osint", _as_list(osint.get("emails")) + _as_list(osint.get("hosts")) + _as_list(osint.get("ips"))),
    ]
    stage_rows: list[dict[str, Any]] = []
    for name, key, items in stage_defs:
        present = key in results or (output_dir / {
            "subdomains": "subdomains.txt",
            "permutations": "stage_02",
            "dns_records": "dns_records.json",
            "live_hosts": "live_hosts.json",
            "ports_and_tls": "ports_and_tls.json",
            "screenshots": "screenshots.json",
            "urls": "urls.txt",
            "js_findings": "js_findings.json",
            "param_findings": "param_findings.json",
            "content_discovery": "content_discovery.json",
            "vuln_findings": "vuln_findings.json",
            "cloud_and_secrets": "cloud_and_secrets.json",
            "osint": "osint.json",
        }[key]).exists()
        reason = ""
        if key == "permutations" and not ctx.scope.allow_active_scans:
            reason = "active scans disabled"
        elif key == "vuln_findings":
            status = vuln.get("status") if isinstance(vuln, dict) else None
            if status == "skipped":
                reason = str(vuln.get("reason") or "required authorization flag disabled")
            elif status == "not_configured":
                reason = str(vuln.get("reason") or "scanner execution not configured")
        elif key == "cloud_and_secrets" and cloud.get("status", {}).get("repository") == "not_requested":
            reason = "no local Git repository provided; cloud enumeration disabled"
        elif key == "cloud_and_secrets" and cloud.get("status", {}).get("cloud_enum") == "disabled":
            reason = "cloud enumeration disabled"
        elif key == "osint":
            reason = "stage not run"
        elif key == "screenshots" and not items:
            reason = "no screenshots recorded (check browser/tool availability)"
        elif key == "content_discovery" and not ctx.scope.allow_active_scans:
            reason = "active scans disabled"
        if key == "vuln_findings" and isinstance(vuln, dict) and vuln.get("status") in {"skipped", "not_configured"}:
            present = False
        if key == "screenshots" and not items:
            present = False
        if key == "content_discovery" and not ctx.scope.allow_active_scans:
            present = False
        if key == "cloud_and_secrets" and cloud.get("status", {}).get("repository") == "not_requested":
            present = False
        stage_rows.append(_stage_row(name, items, len(items), present, reason))

    source_map = results.get("subdomain_sources", {})
    subdomain_rows = [
        {"hostname": hostname, "tools": source_map.get(hostname, []) if isinstance(source_map, dict) else []}
        for hostname in _as_list(subdomains)
    ]
    screenshot_rows = []
    for item in _as_list(screenshots):
        if isinstance(item, dict):
            screenshot_rows.append({**item, "report_path": _relative_screenshot(item.get("screenshot_path"), output_dir)})

    git_secrets = _as_list(cloud.get("git_secrets"))
    js_secrets = _as_list(js_findings.get("secrets"))
    context = {
        "target": ctx.target,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scope": ctx.scope,
        "duration": results.get("scan_duration_seconds"),
        "stages": stage_rows,
        "subdomains": subdomain_rows,
        "live_hosts": _as_list(live_hosts),
        "screenshots": screenshot_rows,
        "ports": ports,
        "tls": tls,
        "urls": _as_list(urls),
        "url_sample": _as_list(urls)[:50],
        "url_total": len(_as_list(urls)),
        "js_endpoints": _as_list(js_findings.get("endpoints")),
        "js_endpoint_sample": _as_list(js_findings.get("endpoints"))[:50],
        "js_secrets_count": len(js_secrets),
        "js_secret_types": _types(js_secrets),
        "param_findings": params,
        "param_count": sum(len(values) for values in params.values() if isinstance(values, list)),
        "content": _as_list(content),
        "content_sample": _as_list(content)[:50],
        "vuln_findings": _finding_groups(vuln),
        "vuln_status": vuln.get("status", "skipped") if isinstance(vuln, dict) else "skipped",
        "vuln_reason": vuln.get("reason", "no output recorded") if isinstance(vuln, dict) else "no output recorded",
        "buckets": _as_list(cloud.get("buckets_found")),
        "git_secret_count": len(git_secrets),
        "git_secret_types": _types(git_secrets),
        "osint_emails": _as_list(osint.get("emails")),
        "osint_hosts": _as_list(osint.get("hosts")),
        "osint_whois": osint.get("whois", osint.get("whois_summary", {})),
        "raw_files_note": "See the JSON files in this scan directory for complete findings.",
    }

    template_dir = Path(__file__).resolve().parent / "templates"
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(("html", "xml")),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    paths = {
        "markdown": output_dir / "report.md",
        "html": output_dir / "report.html",
    }
    for template_name, output_key in (("report.md.j2", "markdown"), ("report.html.j2", "html")):
        template = env.get_template(template_name)
        paths[output_key].write_text(template.render(**context), encoding="utf-8")
    return paths
