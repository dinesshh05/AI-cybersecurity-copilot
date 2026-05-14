from __future__ import annotations

from fastapi import APIRouter

from app.core.config import settings
from app.core.db import get_connection

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "service": settings.app_name}


@router.get("/ready")
def ready() -> dict:
    with get_connection() as conn:
        conn.execute("SELECT 1")
    return {"status": "ready"}

