from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import AsyncIterator


class EventBus:
    """Fan out scan progress events to subscribers for each active scan."""

    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue[dict | None]]] = defaultdict(set)

    async def publish(self, scan_id: str, event: dict) -> None:
        """Publish an event to all currently subscribed clients for a scan."""
        for queue in tuple(self._subscribers.get(scan_id, ())):
            await queue.put(dict(event))
        if event.get("status") in {"finished", "failed", "cancelled"}:
            for queue in tuple(self._subscribers.get(scan_id, ())):
                await queue.put(None)

    async def subscribe(self, scan_id: str) -> AsyncIterator[dict]:
        """Yield scan events until the scan finishes or the subscriber is cancelled."""
        queue: asyncio.Queue[dict | None] = asyncio.Queue()
        self._subscribers[scan_id].add(queue)
        try:
            while True:
                event = await queue.get()
                if event is None:
                    break
                yield event
        finally:
            subscribers = self._subscribers.get(scan_id)
            if subscribers is not None:
                subscribers.discard(queue)
                if not subscribers:
                    self._subscribers.pop(scan_id, None)


event_bus = EventBus()
