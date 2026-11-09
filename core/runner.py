from __future__ import annotations

import asyncio
import json
import shlex
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import aiohttp

from core.dependency_check import ToolStatus
from core.logger import get_logger
from core.registry import ToolSpec

logger = get_logger(__name__)


@dataclass
class RunResult:
    """Outcome of running one tool against a target."""

    tool_name: str
    success: bool
    returncode: int | None
    raw_output_path: Path | None
    stderr_tail: str
    duration_seconds: float
    error: str | None = None


async def _write_stderr_tail(stderr: str, path: Path) -> str:
    tail = (stderr or "")[-500:]
    if tail:
        path.write_text(tail, encoding="utf-8")
    return tail


def _format_run_command(
    tool: ToolSpec,
    target: str,
    output_dir: Path,
    input_file: Path | None = None,
    status: ToolStatus | None = None,
    extra_format_fields: dict[str, str] | None = None,
) -> str:
    out_path = output_dir / f"{tool.name}.raw"
    binary_name = None
    if status is not None and status.resolved_binary:
        binary_name = status.resolved_binary
    elif tool.binary_candidates:
        binary_name = tool.binary_candidates[0]
    elif tool.binary:
        binary_name = tool.binary
    if binary_name is None:
        raise ValueError(f"{tool.name}: no resolved binary available for a command template")

    if status is not None and status.path and shutil.which(binary_name) is None:
        binary_name = status.path

    format_values = {
        "target": target,
        "out": str(out_path),
        "input_file": str(input_file) if input_file is not None else "",
        "binary": binary_name,
    }
    if extra_format_fields:
        format_values.update({key: str(value) for key, value in extra_format_fields.items()})

    formatted = tool.run.command.format(**format_values)
    if "{input_file}" in tool.run.command and input_file is None:
        raise ValueError(f"{tool.name}: run.command requires {input_file!r} but no input_file was supplied")
    return formatted


async def run_tool(
    tool: ToolSpec,
    target: str,
    output_dir: Path,
    input_file: Path | None = None,
    status: ToolStatus | None = None,
    extra_format_fields: dict[str, str] | None = None,
) -> RunResult:
    """Run a tool command safely and always return a structured result."""
    start = time.monotonic()
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / f"{tool.name}.raw"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        command = _format_run_command(tool, target, output_dir, input_file=input_file, status=status, extra_format_fields=extra_format_fields)
        if "{input_file}" in tool.run.command and input_file is None:
            raise ValueError(f"{tool.name}: input_file was required by the run command but not provided")

        # Shell redirection requires a shell, while generic commands should use exec without shell=True.
        use_shell = ">" in command or "|" in command
        argv: list[str]
        if use_shell:
            argv = ["bash", "-lc", command]
        else:
            argv = shlex.split(command)

        proc: asyncio.subprocess.Process
        try:
            if use_shell:
                proc = await asyncio.wait_for(
                    asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE),
                    timeout=tool.run.timeout,
                )
            else:
                proc = await asyncio.wait_for(
                    asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE),
                    timeout=tool.run.timeout,
                )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=tool.run.timeout)
        except asyncio.TimeoutError:
            try:
                if proc is not None:
                    proc.kill()
                    try:
                        proc.terminate()
                    except ProcessLookupError:
                        pass
            except Exception:
                pass
            return RunResult(
                tool_name=tool.name,
                success=False,
                returncode=None,
                raw_output_path=out_path,
                stderr_tail="timeout",
                duration_seconds=time.monotonic() - start,
                error="timeout",
            )

        if stdout and not use_shell:
            out_path.write_bytes(stdout)
        elif stdout and use_shell:
            out_path.write_bytes(stdout)

        stderr_tail = (stderr.decode("utf-8", errors="replace") if stderr else "")[-500:]
        success = proc.returncode == 0
        return RunResult(
            tool_name=tool.name,
            success=success,
            returncode=proc.returncode,
            raw_output_path=out_path,
            stderr_tail=stderr_tail,
            duration_seconds=time.monotonic() - start,
            error=None if success else (stderr_tail or "tool exited with a non-zero code"),
        )
    except Exception as exc:
        return RunResult(
            tool_name=tool.name,
            success=False,
            returncode=None,
            raw_output_path=out_path,
            stderr_tail="",
            duration_seconds=time.monotonic() - start,
            error=str(exc),
        )


async def run_crtsh(target: str, output_dir: Path) -> RunResult:
    """Fetch crt.sh JSON and normalize it into hostnames saved one-per-line."""
    start = time.monotonic()
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / "crtsh.raw"

    url = f"https://crt.sh/?q=%25.{target}&output=json"
    attempts = 0
    last_error: str | None = None

    while attempts < 3:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as response:
                    response.raise_for_status()
                    payload = await response.json()
            names: set[str] = set()
            for entry in payload or []:
                value = entry.get("name_value") if isinstance(entry, dict) else None
                if not value:
                    continue
                for item in str(value).splitlines():
                    cleaned = item.strip().lower().replace("*.", "")
                    if cleaned:
                        names.add(cleaned)
            if names:
                out_path.write_text("\n".join(sorted(names)) + "\n", encoding="utf-8")
                return RunResult(
                    tool_name="crtsh",
                    success=True,
                    returncode=0,
                    raw_output_path=out_path,
                    stderr_tail="",
                    duration_seconds=time.monotonic() - start,
                    error=None,
                )
            break
        except Exception as exc:  # pragma: no cover - network behavior is flaky; keep failure readable
            attempts += 1
            last_error = str(exc)
            if attempts < 3:
                await asyncio.sleep(2 ** attempts)

    return RunResult(
        tool_name="crtsh",
        success=False,
        returncode=None,
        raw_output_path=out_path,
        stderr_tail=last_error or "crt.sh fetch failed",
        duration_seconds=time.monotonic() - start,
        error=last_error or "crt.sh fetch failed",
    )


async def run_tools_parallel(
    tools: list[ToolSpec],
    target: str,
    output_dir: Path,
    input_file: Path | None = None,
    max_concurrent: int = 5,
    status_map: dict[str, ToolStatus] | None = None,
    extra_format_fields: dict[str, str] | None = None,
) -> dict[str, RunResult]:
    """Execute several tools concurrently without allowing one failure to cancel the whole batch."""
    semaphore = asyncio.Semaphore(max_concurrent)

    async def _runner(tool: ToolSpec) -> tuple[str, RunResult]:
        async with semaphore:
            status = None if status_map is None else status_map.get(tool.name)
            if tool.binary is None and not tool.binary_candidates:
                result = await run_crtsh(target, output_dir)
            else:
                result = await run_tool(tool, target, output_dir, input_file=input_file, status=status, extra_format_fields=extra_format_fields)
            return tool.name, result

    results: dict[str, RunResult] = {}
    tasks = [asyncio.create_task(_runner(tool)) for tool in tools]
    for task in asyncio.as_completed(tasks):
        try:
            name, result = await task
        except Exception as exc:  # pragma: no cover - defensive conversion of unexpected task errors
            logger.warning("Tool execution raised an exception: %s", exc)
            continue
        results[name] = result
    return results
