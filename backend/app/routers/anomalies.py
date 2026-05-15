from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.core.auth import CurrentUser, require_roles
from app.services.anomaly import score_log_text
from app.services.storage import get_case, get_case_raw_text

router = APIRouter(prefix="/anomalies", tags=["anomalies"])


@router.post("/score")
def score(log_text: str, _: CurrentUser = Depends(require_roles("analyst", "senior_analyst", "admin"))) -> dict:
    report = score_log_text(log_text)
    return {
        "score": report.score,
        "severity": report.severity,
        "signals": report.signals,
        "features": report.features,
        "model_notes": report.model_notes,
    }


@router.get("/case/{case_id}")
def score_case(case_id: str, _: CurrentUser = Depends(require_roles("analyst", "senior_analyst", "admin"))) -> dict:
    case = get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    raw_text = get_case_raw_text(case_id) or ""
    report = score_log_text(raw_text)
    return {
        "case_id": case_id,
        "title": case["title"],
        "score": report.score,
        "severity": report.severity,
        "signals": report.signals,
        "features": report.features,
        "model_notes": report.model_notes,
    }
