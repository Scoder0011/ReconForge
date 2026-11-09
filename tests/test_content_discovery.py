from __future__ import annotations

import asyncio
import shlex
from pathlib import Path
from types import SimpleNamespace

from core.registry import load_tool_file
from core.runner import _format_run_command
from core.scope import ScopeConfig
from parsers.gobuster import parse as parse_gobuster
from stages import s10_content_discovery


def test_gobuster_registry_loads_and_parser_normalizes_results(tmp_path: Path) -> None:
    """The registered Gobuster command has a parser for its expanded output."""
    registry_path = Path(__file__).parents[1] / "tools_registry" / "10_content_discovery" / "gobuster.yaml"
    tool = load_tool_file(registry_path)
    raw_path = tmp_path / "gobuster.raw"
    raw_path.write_text(
        "https://example.test/admin (Status: 403) [Size: 128]\n"
        "Progress: 100 / 100 (100.00%)\n",
        encoding="utf-8",
    )

    assert tool.name == "gobuster"
    assert tool.output.parser == "gobuster"
    assert parse_gobuster(raw_path) == [
        {"url": "https://example.test/admin", "status": 403, "length": 128}
    ]

    command = _format_run_command(
        tool,
        "example.test",
        tmp_path / "scan output",
        extra_format_fields={
            "target_url": "https://example.test",
            "wordlist_path": str(tmp_path / "word lists" / "common.txt"),
        },
    )
    arguments = shlex.split(command)
    assert arguments[arguments.index("-u") + 1] == "https://example.test"
    assert arguments[arguments.index("-w") + 1] == str(tmp_path / "word lists" / "common.txt")
    assert arguments[arguments.index("-o") + 1] == str(tmp_path / "scan output" / "gobuster.raw")


def test_stage10_only_runs_valid_in_scope_urls(tmp_path: Path, monkeypatch) -> None:
    """Stage 10 sends only authorized, valid live URLs to active tools."""
    wordlist = tmp_path / "wordlist.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr(s10_content_discovery, "_resolve_wordlist_path", lambda: wordlist)

    tool = SimpleNamespace(name="gobuster", output=SimpleNamespace(parser="gobuster"))
    ctx = SimpleNamespace(
        scope=ScopeConfig(
            target_domain="example.test",
            in_scope=["example.test", "*.example.test"],
            out_of_scope=["blocked.example.test"],
            allow_active_scans=True,
        ),
        registry={"10_content_discovery": [tool]},
        target="example.test",
        output_dir=tmp_path,
        tool_statuses={},
        results={},
    )
    calls: list[str] = []

    async def fake_run_tools_parallel(tools, target, output_dir, status_map, extra_format_fields):
        calls.append(extra_format_fields["target_url"])
        raw_path = output_dir / "gobuster.raw"
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(
            f'{extra_format_fields["target_url"]}/admin (Status: 200) [Size: 12]\n',
            encoding="utf-8",
        )
        return {
            "gobuster": SimpleNamespace(
                success=True,
                raw_output_path=raw_path,
                error=None,
            )
        }

    monkeypatch.setattr(s10_content_discovery, "run_tools_parallel", fake_run_tools_parallel)
    findings = asyncio.run(
        s10_content_discovery.run_stage_10(
            ctx,
            [
                {"url": "https://example.test/"},
                {"url": "https://blocked.example.test"},
                {"url": "https://outside.test"},
                {"url": "javascript:alert(1)"},
            ],
        )
    )

    assert calls == ["https://example.test"]
    assert findings == [{"url": "https://example.test/admin", "status": 200, "length": 12}]
