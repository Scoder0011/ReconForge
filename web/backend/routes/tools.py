from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter

from core.dependency_check import check_all
from core.registry import load_all

router = APIRouter(prefix="/api/tools", tags=["tools"])


@router.get("")
async def tool_status() -> list[dict]:
    """Check registered tool availability without installing or invoking scans."""
    registry = load_all(Path("tools_registry"))
    tools = [tool for stage_tools in registry.values() for tool in stage_tools]
    statuses = check_all(tools)
    return [
        {
            "name": tool.name,
            "stage": tool.stage,
            "installed": statuses[tool.name].installed,
            "version": statuses[tool.name].version,
            "path": statuses[tool.name].path,
            "resolved_binary": statuses[tool.name].resolved_binary,
            "error": statuses[tool.name].error,
        }
        for tool in tools
    ]
