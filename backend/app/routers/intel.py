from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.auth import CurrentUser, require_roles
from app.services.intel import lookup_cve, lookup_indicator_summary

router = APIRouter(prefix="/intel", tags=["intel"])


@router.get("/cve/{cve_id}")
def get_cve(cve_id: str, _: CurrentUser = Depends(require_roles("analyst", "senior_analyst", "admin"))) -> dict:
    hit = lookup_cve(cve_id.upper())
    return {
        "source": hit.source,
        "title": hit.title,
        "severity": hit.severity,
        "confidence": hit.confidence,
        "summary": hit.summary,
        "references": hit.references,
        "payload": hit.payload,
    }


@router.get("/indicator")
def get_indicator_summary(value: str, _: CurrentUser = Depends(require_roles("analyst", "senior_analyst", "admin"))) -> dict:
    return lookup_indicator_summary(value)
