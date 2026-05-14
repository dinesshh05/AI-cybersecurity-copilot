from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

import requests
from requests import RequestException

from app.core.settings import settings


@dataclass(slots=True)
class IntelHit:
    source: str
    title: str
    severity: str
    confidence: int
    summary: str
    references: list[str]
    payload: dict


@lru_cache(maxsize=256)
def lookup_cve(cve_id: str) -> IntelHit:
    try:
        response = requests.get(
            settings.nvd_api,
            params={"cveId": cve_id},
            timeout=15,
            headers={"User-Agent": "AI-Cybersecurity-Copilot/0.1"},
        )
        response.raise_for_status()
        payload = response.json()
    except RequestException as exc:
        return IntelHit(
            source="nvd",
            title=cve_id,
            severity="unknown",
            confidence=0,
            summary=f"NVD lookup failed: {exc.__class__.__name__}. Use the cached knowledge base and local log evidence.",
            references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
            payload={"error": str(exc)},
        )
    vulns = payload.get("vulnerabilities", [])
    if not vulns:
        return IntelHit("nvd", cve_id, "unknown", 0, "No NVD record was returned.", [], payload if isinstance(payload, dict) else {})
    cve = vulns[0]["cve"]
    descs = cve.get("descriptions", [])
    summary = next((d["value"] for d in descs if d.get("lang") == "en"), "")
    severity = "medium"
    metrics = cve.get("metrics", {})
    if metrics:
        cvss = next(iter(metrics.values()))[0].get("cvssData", {})
        score = cvss.get("baseScore", 0)
        if score >= 9:
            severity = "critical"
        elif score >= 7:
            severity = "high"
        elif score >= 4:
            severity = "medium"
        else:
            severity = "low"
    return IntelHit(
        source="nvd",
        title=cve.get("id", cve_id),
        severity=severity,
        confidence=85,
        summary=summary,
        references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
        payload=cve,
    )


def lookup_indicator_summary(value: str) -> dict:
    return {
        "value": value,
        "summary": "Use threat intel sources and local RAG to enrich this indicator in the next step.",
        "free_sources": ["NVD", "CISA KEV", "MITRE ATT&CK"],
    }
