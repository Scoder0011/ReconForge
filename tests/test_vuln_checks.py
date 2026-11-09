from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from core.scope import ScopeConfig
from stages.s11_vuln_checks import run_stage_11


def test_stage11_passively_reviews_in_scope_metadata(tmp_path: Path) -> None:
    """Stage 11 records passive indicators and excludes out-of-scope hosts."""
    ctx = SimpleNamespace(
        scope=ScopeConfig(
            target_domain="example.test",
            in_scope=["example.test", "*.example.test"],
            out_of_scope=["blocked.example.test"],
        ),
        output_dir=tmp_path,
        results={
            "ports_and_tls": {
                "tls": [
                    {"host": "www.example.test", "not_after": "2000-01-01T00:00:00Z"},
                    {"host": "blocked.example.test", "not_after": "2000-01-01T00:00:00Z"},
                ]
            }
        },
    )
    live_hosts = [
        {"url": "http://www.example.test/login?token=private"},
        {"url": "http://blocked.example.test"},
        {"url": "https://www.example.test"},
    ]

    result = asyncio.run(
        run_stage_11(ctx, live_hosts, ["http://www.example.test/other", "https://outside.test"])
    )

    assert result["status"] == "complete"
    assert result["mode"] == "passive"
    assert len(result["findings"]) == 2
    assert {finding["name"] for finding in result["findings"]} == {
        "HTTP URL observed",
        "TLS certificate expired",
    }
    assert all("private" not in json.dumps(finding) for finding in result["findings"])
    assert json.loads((tmp_path / "vuln_findings.json").read_text(encoding="utf-8")) == result


def test_stage11_handles_missing_prior_stage_metadata(tmp_path: Path) -> None:
    """A missing TLS or URL dataset produces a valid empty passive report."""
    ctx = SimpleNamespace(
        scope=ScopeConfig(target_domain="example.test", in_scope=["example.test"]),
        output_dir=tmp_path,
        results={},
    )

    result = asyncio.run(run_stage_11(ctx, [], []))

    assert result["status"] == "complete"
    assert result["findings"] == []
