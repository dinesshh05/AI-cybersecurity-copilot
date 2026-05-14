from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass(slots=True)
class Indicator:
    kind: str
    value: str
    severity: str
    confidence: int
    source: str
    detail: str


@dataclass(slots=True)
class EvidenceItem:
    line_number: int
    text: str
    reason: str


@dataclass(slots=True)
class AnalysisResult:
    title: str
    severity: str
    risk_score: int
    detection_summary: str
    reasoning: str
    indicators: list[Indicator] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    model_notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

