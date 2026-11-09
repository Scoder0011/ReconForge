from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

from stages import s05_ports_infra


def test_stage05_continues_when_naabu_fails(tmp_path: Path, monkeypatch) -> None:
    """A failed naabu run should produce an empty port report instead of crashing."""
    naabu_tool = SimpleNamespace(
        name="naabu",
        output=SimpleNamespace(parser="jsonl"),
    )
    ctx = SimpleNamespace(
        registry={"05_ports_infra": [naabu_tool]},
        target="example.test",
        output_dir=tmp_path,
        tool_statuses={},
        results={},
        scope=SimpleNamespace(allow_active_scans=True),
    )

    async def failed_naabu(*args: object, **kwargs: object) -> dict[str, object]:
        return {
            "naabu": SimpleNamespace(
                success=False,
                raw_output_path=None,
                error="tool unavailable",
            )
        }

    monkeypatch.setattr(s05_ports_infra, "run_tools_parallel", failed_naabu)

    result = asyncio.run(
        s05_ports_infra.run_stage_05(ctx, [{"host": "www.example.test", "a": ["192.0.2.1"]}])
    )

    assert result == {"tls": [], "ports": []}
    assert ctx.results["ports"] == []
