from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from core.logger import get_logger

logger = get_logger(__name__)

_ALLOWED_INSTALL_METHODS = {"go", "pip", "pipx", "apt", "cargo", "git", "manual"}


@dataclass
class ToolCheckSpec:
    """Runtime validation instructions for a binary-backed tool."""

    command: Optional[str]
    success_returncode: int = 0
    timeout: int = 10


@dataclass
class ToolInstallSpec:
    """Installation metadata for a tool."""

    method: str
    command: Optional[str] = None
    post_install: Optional[str] = None
    manual_instructions: Optional[str] = None
    timeout: int = 300


@dataclass
class ToolRunSpec:
    """Run configuration for a tool command."""

    command: str
    timeout: int = 600


@dataclass
class ToolOutputSpec:
    """Output expectations for a tool."""

    format: str
    parser: str


@dataclass
class ToolSpec:
    """Single tool definition from a YAML registry entry."""

    name: str
    stage: str
    description: str
    binary: Optional[str]
    binary_candidates: Optional[list[str]] = None
    signature: Optional[str] = None
    check: Optional[ToolCheckSpec] = None
    install: Optional[ToolInstallSpec] = None
    run: Optional[ToolRunSpec] = None
    output: Optional[ToolOutputSpec] = None
    requires_api_key: list[str] = field(default_factory=list)
    notes: Optional[str] = None


class RegistryError(Exception):
    """Raised when a registry entry is missing required data or has bad metadata."""


def _require_key(data: dict[str, Any], key: str, path: Path) -> Any:
    if key not in data or data[key] in (None, ""):
        raise RegistryError(f"{path.name}: missing field '{key}'")
    return data[key]


def load_tool_file(path: Path) -> ToolSpec:
    """Load and validate one tool definition from a registry YAML file."""
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except (OSError, yaml.YAMLError) as exc:  # pragma: no cover - kept readable for callers
        raise RegistryError(f"{path.name}: failed to parse YAML ({exc})") from exc

    if not isinstance(data, dict):
        raise RegistryError(f"{path.name}: YAML root must be a mapping")

    required_fields = ["name", "stage", "description", "check", "install", "run", "output", "requires_api_key"]
    for field_name in required_fields:
        if field_name not in data or data[field_name] is None:
            raise RegistryError(f"{path.name}: missing field '{field_name}'")

    if "binary" not in data and "binary_candidates" not in data:
        raise RegistryError(f"{path.name}: missing field 'binary' or 'binary_candidates'")

    name = _require_key(data, "name", path)
    if str(name) != path.stem:
        raise RegistryError(f"{path.name}: name '{name}' does not match filename stem '{path.stem}'")

    stage = _require_key(data, "stage", path)
    description = _require_key(data, "description", path)
    binary = data.get("binary")
    if binary is not None and not str(binary).strip():
        raise RegistryError(f"{path.name}: field 'binary' cannot be empty")

    binary_candidates = data.get("binary_candidates")
    if binary_candidates is not None:
        if not isinstance(binary_candidates, list):
            raise RegistryError(f"{path.name}: field 'binary_candidates' must be a list")
        cleaned_candidates = [str(item).strip() for item in binary_candidates if str(item).strip()]
        if not cleaned_candidates:
            raise RegistryError(f"{path.name}: field 'binary_candidates' must contain at least one non-empty name")
        binary_candidates = cleaned_candidates

    if binary is None and binary_candidates is None:
        # This is the built-in fetcher case; no local CLI binary is expected.
        pass

    signature = data.get("signature")
    if signature is not None and not str(signature).strip():
        raise RegistryError(f"{path.name}: field 'signature' cannot be empty")

    check_data = data.get("check")
    if not isinstance(check_data, dict):
        raise RegistryError(f"{path.name}: missing field 'check'")
    if binary is not None or binary_candidates is not None:
        _require_key(check_data, "command", path)
    else:
        check_data.setdefault("command", None)
    check = ToolCheckSpec(
        command=check_data.get("command"),
        success_returncode=int(check_data.get("success_returncode", 0)),
        timeout=int(check_data.get("timeout", 10)),
    )

    install_data = data.get("install")
    if not isinstance(install_data, dict):
        raise RegistryError(f"{path.name}: missing field 'install'")
    install_method = str(install_data.get("method", "")).strip()
    if not install_method:
        raise RegistryError(f"{path.name}: missing field 'install.method'")
    if install_method not in _ALLOWED_INSTALL_METHODS:
        raise RegistryError(f"{path.name}: invalid install.method '{install_method}'")
    if install_method == "manual":
        if not install_data.get("manual_instructions"):
            raise RegistryError(f"{path.name}: install.method 'manual' requires manual_instructions")
    elif not install_data.get("command"):
        raise RegistryError(f"{path.name}: missing field 'install.command'")
    install = ToolInstallSpec(
        method=install_method,
        command=install_data.get("command"),
        post_install=install_data.get("post_install"),
        manual_instructions=install_data.get("manual_instructions"),
        timeout=int(install_data.get("timeout", 300)),
    )

    run_data = data.get("run")
    if not isinstance(run_data, dict):
        raise RegistryError(f"{path.name}: missing field 'run'")
    run_command = run_data.get("command")
    if not run_command:
        raise RegistryError(f"{path.name}: missing field 'run.command'")
    run = ToolRunSpec(command=str(run_command), timeout=int(run_data.get("timeout", 600)))

    output_data = data.get("output")
    if not isinstance(output_data, dict):
        raise RegistryError(f"{path.name}: missing field 'output'")
    output_format = output_data.get("format")
    output_parser = output_data.get("parser")
    if not output_format:
        raise RegistryError(f"{path.name}: missing field 'output.format'")
    if not output_parser:
        raise RegistryError(f"{path.name}: missing field 'output.parser'")
    output = ToolOutputSpec(format=str(output_format), parser=str(output_parser))

    requires_api_key = data.get("requires_api_key", [])
    if requires_api_key is None:
        requires_api_key = []
    if not isinstance(requires_api_key, list):
        raise RegistryError(f"{path.name}: field 'requires_api_key' must be a list")

    return ToolSpec(
        name=str(name),
        stage=str(stage),
        description=str(description),
        binary=binary,
        binary_candidates=binary_candidates,
        signature=str(signature) if signature is not None else None,
        check=check,
        install=install,
        run=run,
        output=output,
        requires_api_key=[str(item) for item in requires_api_key],
        notes=data.get("notes"),
    )


def load_stage(registry_dir: Path, stage_name: str) -> list[ToolSpec]:
    """Load all valid tool YAML files in a single stage folder."""
    stage_dir = registry_dir / stage_name
    if not stage_dir.exists():
        return []

    tools: list[ToolSpec] = []
    for path in sorted(stage_dir.iterdir(), key=lambda item: item.name):
        if not path.is_file() or path.suffix.lower() != ".yaml":
            continue
        try:
            tools.append(load_tool_file(path))
        except RegistryError as exc:
            logger.warning("%s", exc)
    return tools


def load_all(registry_dir: Path) -> dict[str, list[ToolSpec]]:
    """Load all tool YAML files grouped by stage folder name."""
    stage_dirs = sorted(
        [path for path in registry_dir.iterdir() if path.is_dir()],
        key=lambda item: item.name,
    )
    return {stage_dir.name: load_stage(registry_dir, stage_dir.name) for stage_dir in stage_dirs}


def get_tool(registry_dir: Path, name: str) -> ToolSpec | None:
    """Look up a tool by name in all stage folders."""
    for stage_tools in load_all(registry_dir).values():
        for tool in stage_tools:
            if tool.name == name:
                return tool
    return None
