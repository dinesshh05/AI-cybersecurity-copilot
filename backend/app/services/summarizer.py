from __future__ import annotations

import json
from dataclasses import asdict
import urllib.error
import urllib.request

from app.core.config import settings
from app.models.domain import AnalysisResult


def _ollama_summary(prompt: str) -> str | None:
    endpoint = f"{settings.ollama_base_url.rstrip('/')}/api/generate"
    payload = {
        "model": settings.ollama_model,
        "prompt": prompt,
        "stream": False,
    }
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=6) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError):
        return None
    return body.get("response")


def build_summary(case_title: str, analysis: AnalysisResult) -> dict:
    prompt = f"""
You are a senior SOC analyst writing an incident summary.
Return a concise executive summary, observed signals, and remediation steps.

Case title: {case_title}
Severity: {analysis.severity}
Risk score: {analysis.risk_score}
Detection summary: {analysis.detection_summary}
Reasoning: {analysis.reasoning}
Indicators: {json.dumps([asdict(indicator) for indicator in analysis.indicators], ensure_ascii=False)}
Remediation suggestions: {json.dumps(analysis.remediation, ensure_ascii=False)}
"""
    llm_summary = _ollama_summary(prompt)
    if llm_summary:
        return {
            "summary": llm_summary.strip(),
            "model": settings.ollama_model,
            "mode": "ollama",
        }

    fallback = (
        f"{case_title} was classified as {analysis.severity.upper()} with a risk score of {analysis.risk_score}. "
        f"{analysis.detection_summary} "
        f"Analyst guidance: {' '.join(analysis.remediation)}"
    )
    return {
        "summary": fallback,
        "model": "heuristic-fallback",
        "mode": "deterministic",
    }
