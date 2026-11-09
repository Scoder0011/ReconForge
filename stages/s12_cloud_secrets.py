from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any

from core.logger import get_logger

if TYPE_CHECKING:
    from core.engine import ScanContext

logger = get_logger(__name__)
_REDACTED_KEYS = {
    "match",
    "raw",
    "rawv2",
    "secret",
    "token",
    "password",
    "credential",
    "apikey",
    "accesskey",
}


def _redact(value: Any) -> Any:
    """Redact fields that may contain credential material while retaining finding metadata."""
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if str(key).replace("_", "").lower() in _REDACTED_KEYS:
                redacted[str(key)] = "[REDACTED]"
            else:
                redacted[str(key)] = _redact(item)
        return redacted
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _parse_json_records(text: str) -> list[dict[str, Any]]:
    """Parse either a JSON document or JSONL scanner output."""
    cleaned = text.strip()
    if not cleaned:
        return []
    try:
        payload = json.loads(cleaned)
    except json.JSONDecodeError:
        payload = []
        for line in cleaned.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                payload.append(item)
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


async def _run_local_scanner(
    scanner: str,
    args: list[str],
    raw_path: Path,
    timeout_seconds: int = 600,
) -> tuple[list[dict[str, Any]], str | None]:
    """Run a local repository scanner with argument-list execution and preserve raw output."""
    binary = shutil.which(scanner)
    if binary is None:
        logger.warning("stage 12: %s skipped — executable not found on PATH", scanner)
        return [], "not-installed"

    process: asyncio.subprocess.Process | None = None
    try:
        process = await asyncio.create_subprocess_exec(
            binary,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        if process is not None:
            process.kill()
            await process.wait()
        logger.warning("stage 12: %s timed out after %s seconds", scanner, timeout_seconds)
        return [], "timeout"
    except OSError as exc:
        logger.warning("stage 12: could not run %s: %s", scanner, exc)
        return [], str(exc)

    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_bytes(stdout or b"")
    stderr_text = stderr.decode("utf-8", errors="replace").strip()
    if process.returncode not in (0, 1):
        logger.warning("stage 12: %s failed with exit code %s: %s", scanner, process.returncode, stderr_text[-500:])
        return [], f"exit_code={process.returncode}"
    if stderr_text:
        logger.info("stage 12: %s completed: %s", scanner, stderr_text[-300:])
    return _parse_json_records(stdout.decode("utf-8", errors="replace")), None


async def run_stage_12(ctx: "ScanContext", target: str, git_repo: str | None) -> dict[str, Any]:
    """Audit an explicitly supplied local Git repository; do not probe cloud providers."""
    del target
    logger.info("stage 12: cloud bucket enumeration is disabled; it would probe third-party providers")
    result: dict[str, Any] = {
        "buckets_found": [],
        "git_secrets": [],
        "status": {"cloud_enum": "disabled", "repository": "not_requested"},
    }

    if git_repo is None:
        logger.info("no git repo provided — skipping trufflehog/gitleaks; pass --git-repo to scan one")
        ctx.results["cloud_and_secrets"] = result
        output_path = ctx.output_dir / "cloud_and_secrets.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result

    repo_path = Path(git_repo).expanduser()
    if "://" in git_repo or not repo_path.is_dir():
        logger.warning("stage 12: --git-repo must be an existing local repository directory; remote URLs are not accepted")
        result["status"]["repository"] = "invalid_local_path"
    else:
        repo_path = repo_path.resolve()
        if not ((repo_path / ".git").exists() or (repo_path / "HEAD").is_file() and (repo_path / "objects").is_dir()):
            logger.warning("stage 12: %s is not a recognizable local Git repository", repo_path)
            result["status"]["repository"] = "not_a_git_repository"
        else:
            logger.info("stage 12: scanning the explicitly supplied local Git repository")
            stage_dir = ctx.output_dir / "stage_12"
            stage_dir.mkdir(parents=True, exist_ok=True)
            trufflehog_records, trufflehog_error = await _run_local_scanner(
                "trufflehog",
                ["git", f"file://{repo_path}", "--json"],
                stage_dir / "trufflehog.raw.jsonl",
            )
            gitleaks_report = stage_dir / "gitleaks.raw.json"
            _, gitleaks_error = await _run_local_scanner(
                "gitleaks",
                [
                    "detect",
                    "--source",
                    str(repo_path),
                    "--report-format",
                    "json",
                    "--report-path",
                    str(gitleaks_report),
                ],
                stage_dir / "gitleaks.stdout.raw",
            )
            gitleaks_records = []
            if gitleaks_report.exists():
                gitleaks_records = _parse_json_records(gitleaks_report.read_text(encoding="utf-8", errors="replace"))
            findings = [
                {"tool": "trufflehog", "finding": _redact(record)}
                for record in trufflehog_records
            ]
            findings.extend(
                {"tool": "gitleaks", "finding": _redact(record)}
                for record in gitleaks_records
            )
            result["git_secrets"] = findings
            result["status"]["repository"] = "scanned"
            result["status"]["trufflehog"] = "failed" if trufflehog_error else "completed"
            result["status"]["gitleaks"] = "failed" if gitleaks_error else "completed"
            logger.info(
                "stage 12: local secret audit completed with %s findings; values are redacted in the summary file",
                len(findings),
            )

    ctx.results["cloud_and_secrets"] = result
    output_path = ctx.output_dir / "cloud_and_secrets.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result
