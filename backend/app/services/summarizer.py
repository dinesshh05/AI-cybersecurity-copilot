from __future__ import annotations

import json
from dataclasses import asdict

import requests
from requests import RequestException

from app.core.config import settings
from app.models.domain import AnalysisResult


def _groq_summary(prompt: str) -> str | None:
    if not settings.groq_api_key:
        return None

    endpoint = f"{settings.groq_api_base.rstrip('/')}/chat/completions"
    payload = {
        "model": settings.groq_model,
        "messages": [
            {
                "role": "system",
                "content": "You are a senior SOC analyst. Produce concise incident summaries with remediation guidance.",
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        "temperature": 0.2,
        "max_tokens": 300,
    }
    try:
        response = requests.post(
            endpoint,
            headers={
                "Authorization": f"Bearer {settings.groq_api_key}",
                "Content-Type": "application/json",
                "User-Agent": "AI-Cybersecurity-Copilot/0.1",
            },
            json=payload,
            timeout=10,
        )
        response.raise_for_status()
        body = response.json()
        return body["choices"][0]["message"]["content"].strip()
    except (RequestException, ValueError, KeyError, IndexError, TypeError):
        return None


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
    llm_summary = _groq_summary(prompt)
    if llm_summary:
        return {
            "summary": llm_summary.strip(),
            "model": settings.groq_model,
            "mode": "groq",
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
