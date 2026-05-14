from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["streams"])


def mount_stream_routes(bus) -> APIRouter:
    @router.websocket("/ws/events")
    async def events_socket(websocket: WebSocket) -> None:
        await bus.connect(websocket)
        try:
            await websocket.send_json({"type": "connection.ready", "payload": {"message": "stream connected"}})
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            await bus.disconnect(websocket)

    return router
