from __future__ import annotations

from urllib.parse import urlsplit

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from core.db import get_scan
from core.events import event_bus

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
    """Forward events already published by the local CLI process to a connected client."""
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
        async for event in event_bus.subscribe(scan_id):
            await websocket.send_json(event)
    except WebSocketDisconnect:
        return
    finally:
        if websocket.client_state.name == "CONNECTED":
            await websocket.close()
