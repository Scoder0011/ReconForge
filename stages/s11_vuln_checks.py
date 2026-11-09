from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from core.logger import get_logger
from core.scope import is_in_scope

if TYPE_CHECKING:
    from core.engine import ScanContext

logger = get_logger(__name__)


def _hostname(value: object) -> str | None:
    """Extract a normalized DNS hostname from a URL or host-like value."""
    candidate = str(value or "").strip()
    if not candidate:
        return None

    try:
        parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
        hostname = (parsed.hostname or "").lower().rstrip(".")
        parsed.port
    except ValueError:
        return None
    return hostname or None


def _expiry_datetime(value: object) -> datetime | None:
    """Parse common ISO-8601 certificate expiry values as timezone-aware UTC."""
    if not value:
        return None
    try:
        expiry = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return expiry.astimezone(timezone.utc)


def _passive_findings(ctx: "ScanContext", live_hosts: list[dict], urls: list[str]) -> list[dict[str, Any]]:
    """Review already-collected URL and TLS metadata without making network requests."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    observed_urls = list(urls)
    observed_urls.extend(
        host.get("url") or host.get("URL")
        for host in live_hosts
        if isinstance(host, dict) and (host.get("url") or host.get("URL"))
    )
    for value in observed_urls:
        try:
            parsed = urlsplit(str(value).strip())
            hostname = (parsed.hostname or "").lower().rstrip(".")
            port = parsed.port
        except ValueError:
            continue
        if (
            parsed.scheme.lower() != "http"
            or not hostname
            or not is_in_scope(hostname, ctx.scope)
        ):
            continue

        authority = hostname if port is None else f"{hostname}:{port}"
        key = ("http_url", authority)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            {
                "tool": "passive_review",
                "name": "HTTP URL observed",
                "severity": "low",
                "matched_at": f"http://{authority}",
                "evidence": "A previously collected URL uses unencrypted HTTP; stage 11 made no network request.",
            }
        )

    tls_payload = ctx.results.get("ports_and_tls", {})
    tls_records = tls_payload.get("tls", []) if isinstance(tls_payload, dict) else []
    if not isinstance(tls_records, list):
        tls_records = ctx.results.get("tls", [])
    if not isinstance(tls_records, list):
        tls_records = []

    now = datetime.now(timezone.utc)
    for record in tls_records:
        if not isinstance(record, dict):
            continue
        hostname = _hostname(record.get("host") or record.get("input") or record.get("hostname"))
        if not hostname or not is_in_scope(hostname, ctx.scope):
            continue

        expiry_value = (
            record.get("not_after")
            or record.get("expiry")
            or record.get("expiration")
            or record.get("valid_to")
        )
        expiry = _expiry_datetime(expiry_value)
        if expiry is None:
            continue
        days_remaining = (expiry - now).days
        if days_remaining >= 30:
            continue

        name = "TLS certificate expired" if days_remaining < 0 else "TLS certificate expires within 30 days"
        severity = "medium" if days_remaining < 0 else "low"
        key = ("tls_expiry", hostname)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            {
                "tool": "passive_review",
                "name": name,
                "severity": severity,
                "matched_at": hostname,
                "expiry": expiry.isoformat(),
                "days_remaining": days_remaining,
                "evidence": "Based on TLS metadata collected in stage 05; stage 11 made no network request.",
            }
        )

    return findings


async def run_stage_11(ctx: "ScanContext", live_hosts: list[dict], urls: list[str]) -> dict[str, Any]:
    """Review previously collected metadata without running active vulnerability scanners."""
    findings = _passive_findings(ctx, live_hosts, urls)
    result: dict[str, Any] = {
        "status": "complete",
        "mode": "passive",
        "reason": "Reviewed in-scope URL and TLS metadata already collected by earlier stages; no requests were sent.",
        "findings": findings,
    }

    ctx.results["vuln_findings"] = result
    output_path: Path = ctx.output_dir / "vuln_findings.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    logger.info("Stage 11 passive review complete: %s findings", len(findings))
    return result
