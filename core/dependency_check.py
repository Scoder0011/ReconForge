from __future__ import annotations

import platform
import shlex
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from core.registry import ToolSpec


@dataclass
class OSInfo:
    """Basic package-manager and runtime metadata used by installers and checks."""

    system: str
    distro_family: Optional[str]
    is_wsl: bool
    has_apt: bool
    has_go: bool
    has_pip: bool
    has_pipx: bool
    has_cargo: bool
    has_git: bool
    is_windows: bool = False
    distro_name: Optional[str] = None


@dataclass
class ToolStatus:
    """Result of checking whether a single tool is installed and usable."""

    installed: bool
    version: Optional[str]
    path: Optional[str]
    error: Optional[str]
    resolved_binary: Optional[str] = None


def detect_os() -> OSInfo:
    """Detect the OS and package-manager capabilities without crashing on unsupported systems."""
    uname_release = platform.uname().release.lower()
    is_wsl = "microsoft" in uname_release
    system_name = platform.system().lower()
    distro_family: Optional[str] = None
    distro_name: Optional[str] = None
    is_windows = False

    if system_name == "darwin":
        system = "darwin"
    elif system_name == "linux":
        system = "linux"
        os_release_path = Path("/etc/os-release")
        if os_release_path.exists():
            try:
                with os_release_path.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        key, _, value = line.partition("=")
                        if key.strip() == "ID":
                            distro_name = value.strip().strip('"')
                        if key.strip() == "NAME":
                            distro_name = value.strip().strip('"')
                        if key.strip() == "ID_LIKE":
                            id_like = value.strip().strip('"')
                            if "debian" in id_like or "ubuntu" in id_like or "kali" in id_like:
                                distro_family = "debian"
                            elif "arch" in id_like:
                                distro_family = "arch"
            except OSError:
                pass
        if distro_family is None:
            distro_family = "unknown"
        if distro_name is None:
            distro_name = "Linux"
    elif system_name == "windows":
        system = "windows"
        is_windows = True
        distro_family = "unknown"
        distro_name = "Windows"
    else:
        system = system_name or "unknown"
        distro_family = "unknown"
        distro_name = system.capitalize()

    if distro_family is None and system == "darwin":
        distro_family = None

    has_apt = system == "linux" and (shutil.which("apt-get") is not None or distro_family == "debian")
    has_go = shutil.which("go") is not None
    has_pip = shutil.which("pip") is not None or shutil.which("pip3") is not None
    has_pipx = shutil.which("pipx") is not None
    has_cargo = shutil.which("cargo") is not None
    has_git = shutil.which("git") is not None

    return OSInfo(
        system=system,
        distro_family=distro_family,
        is_wsl=is_wsl,
        has_apt=has_apt,
        has_go=has_go,
        has_pip=has_pip,
        has_pipx=has_pipx,
        has_cargo=has_cargo,
        has_git=has_git,
        is_windows=is_windows,
        distro_name=distro_name,
    )


def check_tool(tool: ToolSpec) -> ToolStatus:
    """Check whether a tool is on PATH and whether its validation command succeeds."""
    if tool.binary is None and not tool.binary_candidates:
        return ToolStatus(installed=True, version=None, path=None, error=None, resolved_binary=None)

    candidates = list(tool.binary_candidates) if tool.binary_candidates else [tool.binary]
    if not candidates:
        return ToolStatus(installed=True, version=None, path=None, error=None, resolved_binary=None)

    failures: list[str] = []
    for candidate in candidates:
        binary_path = shutil.which(candidate)
        if binary_path is None:
            gopath = None
            try:
                gopath = subprocess.check_output(["go", "env", "GOPATH"], text=True, stderr=subprocess.STDOUT).strip()
            except (FileNotFoundError, subprocess.SubprocessError):
                gopath = None
            if gopath:
                fallback = Path(gopath) / "bin" / candidate
                if fallback.exists():
                    binary_path = str(fallback)
            if binary_path is None:
                failures.append(f"{candidate}: not found on PATH")
                continue

        command = (tool.check.command or f"{candidate} --version").format(binary=candidate)
        argv = shlex.split(command)
        if argv and argv[0] == candidate and binary_path and binary_path != candidate:
            argv[0] = binary_path
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=tool.check.timeout,
                check=False,
            )
            output_text = (completed.stdout or "") + ("\n" if completed.stdout and completed.stderr else "") + (completed.stderr or "")
            captured = output_text.strip()
            version_line = captured.splitlines()[0].strip() if captured else ""

            if tool.signature:
                signature_text = str(tool.signature).lower()
                if signature_text not in (captured.lower() if captured else ""):
                    failures.append(f"{candidate}: found but signature mismatch (missing '{tool.signature}')")
                    continue

            if completed.returncode == tool.check.success_returncode:
                return ToolStatus(
                    installed=True,
                    version=version_line or None,
                    path=binary_path,
                    error=None,
                    resolved_binary=candidate,
                )
            failures.append(f"{candidate}: check command exited with code {completed.returncode} (expected {tool.check.success_returncode})")
        except subprocess.TimeoutExpired as exc:
            failures.append(f"{candidate}: timed out ({exc})")
        except FileNotFoundError as exc:
            failures.append(f"{candidate}: file not found ({exc})")
        except Exception as exc:  # pragma: no cover - defensive guard for unexpected runtime issues
            failures.append(f"{candidate}: {exc}")

    joined = "; ".join(failures) if failures else "unknown failure"
    return ToolStatus(installed=False, version=None, path=None, error=joined, resolved_binary=None)


def check_all(tools: list[ToolSpec], max_workers: int = 8) -> dict[str, ToolStatus]:
    """Check many tools concurrently because subprocess probes are mostly I/O-bound."""
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(check_tool, tool): tool for tool in tools}
        results: dict[str, ToolStatus] = {}
        for future in future_map:
            tool = future_map[future]
            results[tool.name] = future.result()
    return results
