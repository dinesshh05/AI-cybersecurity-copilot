from __future__ import annotations

import re
from dataclasses import dataclass

from app.services.analyzer import AUTH_FAILURE_PATTERN, COMMAND_PATTERN, CVE_PATTERN, IP_PATTERN, MALWARE_PATTERN


@dataclass(slots=True)
class AnomalyReport:
    score: int
    severity: str
    signals: list[str]
    features: dict[str, int]


def _severity(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def score_log_text(log_text: str) -> AnomalyReport:
    lines = [line for line in log_text.splitlines() if line.strip()]
    failed = len(AUTH_FAILURE_PATTERN.findall(log_text))
    commands = len(COMMAND_PATTERN.findall(log_text))
    malware = len(MALWARE_PATTERN.findall(log_text))
    ips = len(set(IP_PATTERN.findall(log_text)))
    cves = len(set(match.upper() for match in CVE_PATTERN.findall(log_text)))
    privilege = len(re.findall(r"\b(sudo|admin|privilege|root)\b", log_text, flags=re.IGNORECASE))

    score = min(100, 8 + failed * 8 + commands * 12 + malware * 15 + ips * 5 + cves * 25 + privilege * 4)
    signals: list[str] = []
    if failed >= 3:
        signals.append("Burst of authentication failures")
    if commands:
        signals.append("Suspicious command execution pattern")
    if malware:
        signals.append("Malware-related terminology")
    if cves:
        signals.append("CVE references in log content")
    if ips >= 2:
        signals.append("Multiple unique IPs observed")
    if privilege:
        signals.append("Privilege-related keywords present")

    if not signals:
        signals.append("No strong anomaly pattern detected")

    return AnomalyReport(
        score=score,
        severity=_severity(score),
        signals=signals,
        features={
            "lines": len(lines),
            "failed_logins": failed,
            "commands": commands,
            "malware_terms": malware,
            "unique_ips": ips,
            "cves": cves,
            "privilege_terms": privilege,
        },
    )

