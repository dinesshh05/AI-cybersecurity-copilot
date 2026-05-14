from __future__ import annotations

import asyncio

from fastapi import WebSocket


class EventBus:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._clients.add(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(websocket)

    async def publish(self, event: dict) -> None:
        async with self._lock:
            clients = list(self._clients)
        stale_clients: list[WebSocket] = []
        for client in clients:
            try:
                await client.send_json(event)
            except Exception:
                stale_clients.append(client)
        if stale_clients:
            async with self._lock:
                for client in stale_clients:
                    self._clients.discard(client)


def build_event(event_type: str, payload: dict) -> dict:
    return {"type": event_type, "payload": payload}


event_bus = EventBus()
