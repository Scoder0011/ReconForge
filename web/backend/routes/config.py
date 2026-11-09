from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/config", tags=["config"])
SCOPE_FILE = Path("config") / "scope.yaml"


@router.get("/scope")
async def get_scope() -> dict[str, Any]:
    """Return the current scope configuration as JSON; scope is read-only over HTTP."""
    if not SCOPE_FILE.exists():
        return {}
    try:
        data = yaml.safe_load(SCOPE_FILE.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise HTTPException(status_code=500, detail=f"Could not read scope configuration: {exc}") from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=500, detail="Scope configuration root must be a mapping")
    return data
