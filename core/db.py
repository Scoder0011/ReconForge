from __future__ import annotations

import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite


def _database_path() -> Path:
    configured = os.environ.get("RECONFORGE_DB")
    return Path(configured).expanduser() if configured else Path("output") / "scans.sqlite3"


async def _connect() -> aiosqlite.Connection:
    path = _database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = await aiosqlite.connect(path)
    connection.row_factory = aiosqlite.Row
    await connection.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL,
            output_dir TEXT NOT NULL
        )
        """
    )
    await connection.commit()
    return connection


@asynccontextmanager
async def _connection():
    connection = await _connect()
    try:
        yield connection
    finally:
        await connection.close()


async def create_scan(target: str, output_dir: str | Path | None = None) -> str:
    """Create a scan-history entry and return its opaque identifier."""
    scan_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    result_dir = Path(output_dir) if output_dir is not None else Path("output") / target / scan_id
    async with _connection() as connection:
        await connection.execute(
            "INSERT INTO scans (id, target, started_at, status, output_dir) VALUES (?, ?, ?, ?, ?)",
            (scan_id, target, started_at, "running", str(result_dir.resolve())),
        )
        await connection.commit()
    return scan_id


async def update_scan_status(scan_id: str, status: str) -> None:
    """Update scan state; terminal states also record a finish timestamp."""
    finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds") if status in {"completed", "failed", "cancelled"} else None
    async with _connection() as connection:
        await connection.execute(
            "UPDATE scans SET status = ?, finished_at = COALESCE(?, finished_at) WHERE id = ?",
            (status, finished_at, scan_id),
        )
        await connection.commit()


async def list_scans() -> list[dict[str, Any]]:
    """Return scan history newest first."""
    async with _connection() as connection:
        cursor = await connection.execute(
            "SELECT id, target, started_at, finished_at, status, output_dir FROM scans ORDER BY started_at DESC"
        )
        rows = await cursor.fetchall()
    return [dict(row) for row in rows]


async def get_scan(scan_id: str) -> dict[str, Any] | None:
    """Return one scan-history entry, or None when its identifier is unknown."""
    async with _connection() as connection:
        cursor = await connection.execute(
            "SELECT id, target, started_at, finished_at, status, output_dir FROM scans WHERE id = ?",
            (scan_id,),
        )
        row = await cursor.fetchone()
    return dict(row) if row is not None else None


async def delete_scan(scan_id: str) -> bool:
    """Delete one scan-history entry without removing its output files."""
    async with _connection() as connection:
        cursor = await connection.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        await connection.commit()
        return cursor.rowcount > 0
