from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.core.auth import CurrentUser, require_roles
from app.services.storage import get_case, list_cases, seed_demo_case

router = APIRouter(prefix="/cases", tags=["cases"])


@router.get("")
def get_cases(limit: int = 50, _: CurrentUser = Depends(require_roles("analyst", "senior_analyst", "admin"))) -> dict:
    return {"items": list_cases(limit=limit)}


@router.get("/{case_id}")
def get_case_detail(case_id: str, _: CurrentUser = Depends(require_roles("analyst", "senior_analyst", "admin"))) -> dict:
    case = get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.post("/demo")
def create_demo_case(_: CurrentUser = Depends(require_roles("analyst", "senior_analyst", "admin"))) -> dict:
    case_id = seed_demo_case()
    if case_id is None:
        return {"status": "already_seeded"}
    return {"status": "seeded", "case_id": case_id}
