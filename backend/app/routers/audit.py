from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.auth import CurrentUser, require_roles
from app.services.auth_store import list_audit_events

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/events")
def get_audit_events(limit: int = 100, _: CurrentUser = Depends(require_roles("admin"))) -> dict:
    return {"items": list_audit_events(limit=limit)}
