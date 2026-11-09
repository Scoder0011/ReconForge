from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ScopeConfig:
    """Authority and host-scope configuration for a scan target."""

    target_domain: str
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    allow_active_scans: bool = False
    allow_vuln_scans: bool = False


class ScopeViolation(Exception):
    """Raised when an active scan is attempted without explicit authorization."""


def _normalize_patterns(patterns: Any) -> list[str]:
    if patterns is None:
        return []
    if not isinstance(patterns, list):
        return [str(patterns)]
    return [str(value).strip().lower() for value in patterns if str(value).strip()]


def load_scope(target_domain: str, scope_file: Path | None) -> ScopeConfig:
    """Load explicit scope or create a passive-only default with a warning."""
    target = (target_domain or "").strip().lower()
    if not target:
        raise ValueError("target_domain must be non-empty")

    default_scope = ScopeConfig(
        target_domain=target,
        in_scope=[f"*.{target}", target],
        out_of_scope=[],
        allow_active_scans=False,
        allow_vuln_scans=False,
    )

    if scope_file is None:
        logger.warning(
            "No scope file provided for '%s'; using passive-only default scope. Create config/scope.yaml before running active stages.",
            target,
        )
        return default_scope

    if not scope_file.exists():
        logger.warning(
            "Scope file '%s' was not found; using passive-only default scope for '%s'. Create it before enabling active scans.",
            scope_file,
            target,
        )
        return default_scope

    try:
        with scope_file.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except (OSError, yaml.YAMLError) as exc:
        logger.warning("Failed to parse scope file '%s': %s; using default passive-only scope.", scope_file, exc)
        return default_scope

    config_data = data if isinstance(data, dict) else {}
    in_scope = _normalize_patterns(config_data.get("in_scope", []))
    out_of_scope = _normalize_patterns(config_data.get("out_of_scope", []))
    if not in_scope:
        in_scope = [f"*.{target}", target]

    return ScopeConfig(
        target_domain=target,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
        allow_active_scans=bool(config_data.get("allow_active_scans", False)),
        allow_vuln_scans=bool(config_data.get("allow_vuln_scans", False)),
    )


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_in_scope(hostname: str, scope: ScopeConfig) -> bool:
    """Return True only when a hostname matches explicit in-scope wildcards and is not excluded."""
    host = (hostname or "").strip().lower()
    if not host:
        return False

    if _looks_like_ip(host):
        return False

    for pattern in scope.out_of_scope:
        if fnmatch.fnmatchcase(host, pattern.lower()):
            return False

    for pattern in scope.in_scope:
        if fnmatch.fnmatchcase(host, pattern.lower()):
            return True

    return False


def filter_in_scope(hostnames: list[str], scope: ScopeConfig) -> tuple[list[str], list[str]]:
    """Return (kept, dropped) while logging the reason each hostname was dropped."""
    kept: list[str] = []
    dropped: list[str] = []

    for hostname in hostnames:
        value = (hostname or "").strip().lower()
        if not value:
            logger.info("Dropped empty hostname while filtering scope")
            dropped.append(value)
            continue

        if _looks_like_ip(value):
            logger.info("Dropped '%s' because it is IP-like rather than a hostname match.", value)
            dropped.append(value)
            continue

        if any(fnmatch.fnmatchcase(value, pattern.lower()) for pattern in scope.out_of_scope):
            logger.info("Dropped '%s' because it matches an out-of-scope pattern.", value)
            dropped.append(value)
            continue

        if is_in_scope(value, scope):
            kept.append(value)
        else:
            logger.info("Dropped '%s' because it did not match any in-scope pattern.", value)
            dropped.append(value)

    return kept, dropped


def ensure_active_authorization(scope: ScopeConfig) -> None:
    """Raise a ScopeViolation if a caller tries to use active stages without explicit approval."""
    if not scope.allow_active_scans:
        raise ScopeViolation("Active scans are disabled; set allow_active_scans=true only with explicit authorization.")
