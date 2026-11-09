from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/config", tags=["config"])
SCOPE_FILE = Path("config") / "scope.yaml"
_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _validated_patterns(value: Any, field: str) -> list[str]:
    """Validate explicit DNS scope patterns, allowing only a leading wildcard."""
    if not isinstance(value, list):
        raise HTTPException(status_code=422, detail=f"{field} must be a list of domain names")

    patterns: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise HTTPException(status_code=422, detail=f"{field} entries must be strings")
        pattern = item.strip().lower()
        domain = pattern[2:] if pattern.startswith("*.") else pattern
        labels = domain.split(".")
        if (
            len(domain) > 253
            or len(labels) < 2
            or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels)
            or ("*" in domain)
        ):
            raise HTTPException(status_code=422, detail=f"Invalid domain pattern in {field}: {item!r}")
        if pattern not in patterns:
            patterns.append(pattern)
    return patterns


@router.get("/scope")
async def get_scope() -> dict[str, Any]:
    """Return the current scope configuration as JSON."""
    if not SCOPE_FILE.exists():
        return {}
    try:
        data = yaml.safe_load(SCOPE_FILE.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise HTTPException(status_code=500, detail=f"Could not read scope configuration: {exc}") from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=500, detail="Scope configuration root must be a mapping")
    return data


@router.put("/scope")
async def update_scope(payload: dict[str, Any]) -> dict[str, Any]:
    """Update domain patterns and explicit vulnerability-scan consent."""
    unexpected = set(payload) - {"in_scope", "out_of_scope", "allow_vuln_scans"}
    if unexpected:
        raise HTTPException(
            status_code=422,
            detail=f"Only in_scope and out_of_scope may be edited; unexpected fields: {', '.join(sorted(unexpected))}",
        )
    if "in_scope" not in payload or "out_of_scope" not in payload:
        raise HTTPException(status_code=422, detail="Both in_scope and out_of_scope are required")
    if "allow_vuln_scans" in payload and not isinstance(payload["allow_vuln_scans"], bool):
        raise HTTPException(status_code=422, detail="allow_vuln_scans must be a boolean")

    in_scope = _validated_patterns(payload["in_scope"], "in_scope")
    out_of_scope = _validated_patterns(payload["out_of_scope"], "out_of_scope")
    try:
        existing = yaml.safe_load(SCOPE_FILE.read_text(encoding="utf-8")) if SCOPE_FILE.exists() else {}
        if existing is None:
            existing = {}
        if not isinstance(existing, dict):
            raise HTTPException(status_code=500, detail="Scope configuration root must be a mapping")
        updated = dict(existing)
        updated["in_scope"] = in_scope
        updated["out_of_scope"] = out_of_scope
        if "allow_vuln_scans" in payload:
            updated["allow_vuln_scans"] = payload["allow_vuln_scans"]
        SCOPE_FILE.parent.mkdir(parents=True, exist_ok=True)
        SCOPE_FILE.write_text(yaml.safe_dump(updated, sort_keys=False), encoding="utf-8")
    except (OSError, yaml.YAMLError) as exc:
        raise HTTPException(status_code=500, detail=f"Could not update scope configuration: {exc}") from exc
    return updated
