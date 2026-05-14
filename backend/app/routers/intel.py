from __future__ import annotations

from fastapi import APIRouter

from app.services.intel import lookup_cve, lookup_indicator_summary

router = APIRouter(prefix="/intel", tags=["intel"])


@router.get("/cve/{cve_id}")
def get_cve(cve_id: str) -> dict:
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
def get_indicator_summary(value: str) -> dict:
    return lookup_indicator_summary(value)

