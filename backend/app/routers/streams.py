from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.auth import decode_access_token
from app.services.auth_store import record_audit_event

router = APIRouter(tags=["streams"])


def mount_stream_routes(bus) -> APIRouter:
    @router.websocket("/ws/events")
    async def events_socket(websocket: WebSocket) -> None:
        token = websocket.query_params.get("token", "")
        user = None
        if token:
            try:
                user = decode_access_token(token)
            except Exception:
                await websocket.close(code=1008)
                return
        else:
            await websocket.close(code=1008)
            return

        await bus.connect(websocket)
        record_audit_event(user.username, user.role, "ws.connect", "success", resource_type="websocket", metadata={"path": "/api/v1/ws/events"})
        try:
            await websocket.send_json({"type": "connection.ready", "payload": {"message": "stream connected"}})
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            record_audit_event(user.username, user.role, "ws.disconnect", "success", resource_type="websocket", metadata={"path": "/api/v1/ws/events"})
            await bus.disconnect(websocket)

    return router
