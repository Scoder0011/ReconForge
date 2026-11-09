from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from core import engine


def test_dns_stage_processes_all_batches(tmp_path: Path, monkeypatch) -> None:
    """DNS batching should retain results from every input batch."""
    tool = SimpleNamespace(name="dnsx", output=SimpleNamespace(parser="jsonl"))
    ctx = SimpleNamespace(
        registry={"03_dns": [tool]},
        target="unit.test",
        output_dir=tmp_path,
        tool_statuses={},
        results={},
    )
    processed: list[list[str]] = []

    async def fake_run_tools_parallel(
        tools: list[object],
        target: str,
        output_dir: Path,
        input_file: Path,
        status_map: dict[str, object],
    ) -> dict[str, object]:
        hosts = input_file.read_text(encoding="utf-8").splitlines()
        processed.append(hosts)
        output_dir.mkdir(parents=True, exist_ok=True)
        raw_path = output_dir / "dnsx.raw"
        raw_path.write_text(
            json.dumps({"host": hosts[0], "status_code": "NOERROR"}),
            encoding="utf-8",
        )
        return {
            "dnsx": SimpleNamespace(
                success=True,
                raw_output_path=raw_path,
                error=None,
            )
        }

    monkeypatch.setattr(engine, "run_tools_parallel", fake_run_tools_parallel)
    hostnames = [f"host-{index}.unit.test" for index in range(5001)]

    records = asyncio.run(engine.run_stage_03_dns(ctx, hostnames))

    assert [len(batch) for batch in processed] == [5000, 1]
    assert len(records) == 2
    assert ctx.results["dns_timeout"] is False
