from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from core.db import get_scan, list_scan_events

router = APIRouter(tags=["events"])
_LOCAL_HOSTS = {"127.0.0.1", "localhost"}


def _is_local_host(value: str | None) -> bool:
    if not value:
        return False
    try:
        return (urlsplit("//" + value).hostname or "").lower() in _LOCAL_HOSTS
    except ValueError:
        return False


@router.websocket("/ws/scans/{scan_id}")
async def scan_events(websocket: WebSocket, scan_id: str) -> None:
    """Forward persisted progress events from CLI scans to local dashboard clients."""
    origin = websocket.headers.get("origin")
    if not _is_local_host(websocket.headers.get("host")) or (
        origin and not _is_local_host(urlsplit(origin).netloc)
    ):
        await websocket.close(code=4403, reason="Localhost access only")
        return
    if await get_scan(scan_id) is None:
        await websocket.close(code=4404, reason="Scan not found")
        return
    await websocket.accept()
    try:
        last_event_id = 0
        while True:
            events = await list_scan_events(scan_id, last_event_id)
            for event_id, event in events:
                await websocket.send_json(event)
                last_event_id = event_id
                if event.get("status") in {"finished", "failed", "cancelled"}:
                    return

            scan = await get_scan(scan_id)
            if scan is None:
                return
            if scan["status"] in {"completed", "failed", "cancelled"}:
                await websocket.send_json({
                    "stage": "pipeline",
                    "status": scan["status"],
                    "reason": "scan finished before a terminal progress event was recorded",
                })
                return
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        return
    finally:
        if websocket.client_state.name == "CONNECTED":
            await websocket.close()
