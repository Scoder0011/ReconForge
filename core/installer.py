from __future__ import annotations

import os
import shlex
import subprocess
from dataclasses import dataclass
from typing import Optional


def _ensure_go_bin_on_path() -> str | None:
    """Add GOPATH/bin to PATH so newly installed Go tools are immediately usable."""
    try:
        gopath = subprocess.check_output(["go", "env", "GOPATH"], text=True, stderr=subprocess.STDOUT).strip()
    except (FileNotFoundError, subprocess.SubprocessError):
        return None

    gopath = gopath or os.path.join(os.path.expanduser("~"), "go")
    go_bin = os.path.join(gopath, "bin")
    path_entries = os.environ.get("PATH", "").split(os.pathsep)
    if go_bin not in path_entries:
        os.environ["PATH"] = f"{go_bin}{os.pathsep}{os.environ.get('PATH', '')}".rstrip(os.pathsep)
    return go_bin

from core.dependency_check import OSInfo
from core.registry import ToolSpec


@dataclass
class InstallResult:
    """Outcome of attempting a tool installation."""

    tool_name: str
    success: bool
    method: str
    output: str
    error: Optional[str] = None


def _run_command(command: str, timeout_seconds: int = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        shlex.split(command),
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )


def install_tool(tool: ToolSpec, os_info: OSInfo, dry_run: bool = False) -> InstallResult:
    """Install a tool when possible and always surface a readable result.

    For manual installs, ``error='manual'`` is used intentionally so callers can distinguish
    a tool that needs user guidance from an actual command failure.
    """
    method = tool.install.method

    if method == "manual":
        instructions = tool.install.manual_instructions or "Manual installation required."
        return InstallResult(
            tool_name=tool.name,
            success=False,
            method=method,
            output=instructions,
            error="manual",
        )

    if dry_run:
        commands: list[str] = [tool.install.command] if tool.install.command else []
        if tool.install.post_install:
            commands.append(tool.install.post_install)
        output = "\n".join(command for command in commands if command)
        if not output:
            output = f"dry-run: {tool.name} ({method})"
        return InstallResult(tool_name=tool.name, success=False, method=method, output=output, error=None)

    if method == "go":
        if not os_info.has_go:
            return InstallResult(
                tool_name=tool.name,
                success=False,
                method=method,
                output="Go is not installed — install it first, see https://go.dev/doc/install",
                error="missing-prerequisite",
            )
        command = tool.install.command or ""
        if not command:
            return InstallResult(tool_name=tool.name, success=False, method=method, output="No install command configured.", error="missing-command")
        try:
            completed = _run_command(command, timeout_seconds=getattr(tool.install, "timeout", 300))
            output_parts = []
            if completed.stdout.strip():
                output_parts.append(completed.stdout.strip())
            if completed.stderr.strip():
                output_parts.append(completed.stderr.strip())
            if completed.returncode != 0:
                return InstallResult(
                    tool_name=tool.name,
                    success=False,
                    method=method,
                    output="\n".join(output_parts) or "Go install failed.",
                    error=f"exit_code={completed.returncode}",
                )

            go_bin = _ensure_go_bin_on_path()
            if go_bin:
                path_entries = os.environ.get("PATH", "").split(os.pathsep)
                if go_bin in path_entries:
                    output_parts.append(f"Go tools are now available via {go_bin}.")
                else:
                    output_parts.append(f"Warning: {go_bin} is not on PATH. Add it to your shell profile to use the installed tools.")
            result_output = "\n".join(output_parts) if output_parts else "Go install completed."
            if tool.install.post_install:
                post_install_result = _run_command(tool.install.post_install, timeout_seconds=300)
                if post_install_result.returncode != 0:
                    return InstallResult(tool_name=tool.name, success=False, method=method, output=result_output + "\n" + (post_install_result.stderr or post_install_result.stdout or "Post-install step failed."), error=f"exit_code={post_install_result.returncode}")
                if post_install_result.stdout.strip():
                    result_output += "\n" + post_install_result.stdout.strip()
                if post_install_result.stderr.strip():
                    result_output += "\n" + post_install_result.stderr.strip()
            return InstallResult(tool_name=tool.name, success=True, method=method, output=result_output)
        except (OSError, subprocess.SubprocessError) as exc:
            return InstallResult(tool_name=tool.name, success=False, method=method, output=str(exc), error=str(exc))

    if method in {"pip", "pipx"}:
        prerequisite_name = "pip" if method == "pip" else "pipx"
        has_prerequisite = os_info.has_pip if method == "pip" else os_info.has_pipx
        if not has_prerequisite:
            return InstallResult(
                tool_name=tool.name,
                success=False,
                method=method,
                output=f"{prerequisite_name} is not installed — install it first.",
                error="missing-prerequisite",
            )
        command = tool.install.command or ""
        if not command:
            return InstallResult(tool_name=tool.name, success=False, method=method, output="No install command configured.", error="missing-command")
        if (
            (command.startswith("pip ") or command.startswith("pip3 ") or command.startswith("python -m pip ") or command.startswith("python3 -m pip "))
            and "--break-system-packages" not in command
        ):
            command = f"{command} --break-system-packages"
        try:
            completed = _run_command(command, timeout_seconds=getattr(tool.install, "timeout", 300))
            output = (completed.stdout or completed.stderr or "Install command completed.").strip()
            if completed.returncode != 0:
                return InstallResult(tool_name=tool.name, success=False, method=method, output=output, error=f"exit_code={completed.returncode}")
            if tool.install.post_install:
                post_completed = _run_command(tool.install.post_install, timeout_seconds=300)
                if post_completed.returncode != 0:
                    return InstallResult(tool_name=tool.name, success=False, method=method, output=output + "\n" + (post_completed.stderr or post_completed.stdout or "Post-install step failed."), error=f"exit_code={post_completed.returncode}")
                output += "\n" + (post_completed.stdout or post_completed.stderr or "Post-install completed.")
            return InstallResult(tool_name=tool.name, success=True, method=method, output=output)
        except (OSError, subprocess.SubprocessError) as exc:
            return InstallResult(tool_name=tool.name, success=False, method=method, output=str(exc), error=str(exc))

    if method == "apt":
        if not os_info.has_apt:
            return InstallResult(
                tool_name=tool.name,
                success=False,
                method=method,
                output="APT is unavailable on this system — install a Debian/Ubuntu-like base or use a manual install path.",
                error="missing-prerequisite",
            )
        command = tool.install.command or ""
        if not command:
            return InstallResult(tool_name=tool.name, success=False, method=method, output="No install command configured.", error="missing-command")
        if "apt-get" not in command and "apt " not in command:
            command = f"sudo apt-get install -y {command}"
        try:
            completed = _run_command(command, timeout_seconds=getattr(tool.install, "timeout", 300))
            output = (completed.stdout or completed.stderr or "APT install completed.").strip()
            if completed.returncode != 0:
                return InstallResult(tool_name=tool.name, success=False, method=method, output=output, error=f"exit_code={completed.returncode}")
            if tool.install.post_install:
                post_completed = _run_command(tool.install.post_install, timeout_seconds=300)
                if post_completed.returncode != 0:
                    return InstallResult(tool_name=tool.name, success=False, method=method, output=output + "\n" + (post_completed.stderr or post_completed.stdout or "Post-install step failed."), error=f"exit_code={post_completed.returncode}")
                output += "\n" + (post_completed.stdout or post_completed.stderr or "Post-install completed.")
            return InstallResult(tool_name=tool.name, success=True, method=method, output=output)
        except (OSError, subprocess.SubprocessError) as exc:
            return InstallResult(tool_name=tool.name, success=False, method=method, output=str(exc), error=str(exc))

    if method in {"cargo", "git"}:
        prerequisite_name = "cargo" if method == "cargo" else "git"
        has_prerequisite = os_info.has_cargo if method == "cargo" else os_info.has_git
        if not has_prerequisite:
            return InstallResult(
                tool_name=tool.name,
                success=False,
                method=method,
                output=f"{prerequisite_name} is not installed — install it first.",
                error="missing-prerequisite",
            )
        command = tool.install.command or ""
        if not command:
            return InstallResult(tool_name=tool.name, success=False, method=method, output="No install command configured.", error="missing-command")
        try:
            completed = _run_command(command, timeout_seconds=getattr(tool.install, "timeout", 300))
            output = (completed.stdout or completed.stderr or "Install command completed.").strip()
            if completed.returncode != 0:
                return InstallResult(tool_name=tool.name, success=False, method=method, output=output, error=f"exit_code={completed.returncode}")
            if tool.install.post_install:
                post_completed = _run_command(tool.install.post_install, timeout_seconds=300)
                if post_completed.returncode != 0:
                    return InstallResult(tool_name=tool.name, success=False, method=method, output=output + "\n" + (post_completed.stderr or post_completed.stdout or "Post-install step failed."), error=f"exit_code={post_completed.returncode}")
                output += "\n" + (post_completed.stdout or post_completed.stderr or "Post-install completed.")
            return InstallResult(tool_name=tool.name, success=True, method=method, output=output)
        except (OSError, subprocess.SubprocessError) as exc:
            return InstallResult(tool_name=tool.name, success=False, method=method, output=str(exc), error=str(exc))

    return InstallResult(
        tool_name=tool.name,
        success=False,
        method=method,
        output=f"Unsupported installation method: {method}",
        error="unsupported-method",
    )


def install_missing(tools: list[ToolSpec], statuses: dict[str, object], os_info: OSInfo, dry_run: bool = False) -> list[InstallResult]:
    """Install only the tools that are currently missing, keeping the input order stable."""
    results: list[InstallResult] = []
    for tool in tools:
        status = statuses.get(tool.name)
        if status is not None and getattr(status, "installed", False):
            continue
        results.append(install_tool(tool, os_info, dry_run=dry_run))
    return results
