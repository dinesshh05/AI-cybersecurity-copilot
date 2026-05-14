from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import asdict

from app.models.domain import AnalysisResult, EvidenceItem, Indicator
from app.services.intelligence import lookup_cve, lookup_ip_reputation, map_command_to_technique

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
AUTH_FAILURE_PATTERN = re.compile(
    r"(failed password|authentication failure|invalid user|login failed|denied access|unauthorized)",
    re.IGNORECASE,
)
COMMAND_PATTERN = re.compile(r"(powershell|cmd\.exe|bash -c|curl\s|wget\s|mimikatz|chmod\s+777)", re.IGNORECASE)
MALWARE_PATTERN = re.compile(r"(ransomware|trojan|malware|shellcode|exploit|beaconing|c2)", re.IGNORECASE)


def _severity_from_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _title_from_hits(lines: list[str], cves: list[str], ips: list[str]) -> str:
    if cves:
        return f"Potential vulnerability activity centered on {cves[0]}"
    if ips:
        return f"Suspicious network activity involving {ips[0]}"
    if lines:
        return "Suspicious log activity"
    return "Log upload received"


def analyze_log_text(log_text: str, source_name: str = "upload") -> AnalysisResult:
    lines = [line.rstrip() for line in log_text.splitlines() if line.strip()]
    lower_blob = log_text.lower()
    ips = sorted(set(IP_PATTERN.findall(log_text)))
    cves = sorted(set(match.upper() for match in CVE_PATTERN.findall(log_text)))
    hashes = sorted(set(HASH_PATTERN.findall(log_text)))

    indicators: list[Indicator] = []
    evidence: list[EvidenceItem] = []
    remediation: list[str] = []
    reasoning_parts: list[str] = []

    score = 10

    failed_logins = 0
    for line_number, line in enumerate(lines, start=1):
        line_lower = line.lower()
        if AUTH_FAILURE_PATTERN.search(line):
            failed_logins += 1
            evidence.append(EvidenceItem(line_number=line_number, text=line, reason="Authentication failure pattern"))
        if COMMAND_PATTERN.search(line):
            evidence.append(EvidenceItem(line_number=line_number, text=line, reason="Suspicious command or script execution"))
        if MALWARE_PATTERN.search(line):
            evidence.append(EvidenceItem(line_number=line_number, text=line, reason="Malware-related keyword"))

    for ip in ips:
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            continue
        intel = lookup_ip_reputation(ip)
        indicators.append(
            Indicator(
                kind="ip",
                value=ip,
                severity=intel.severity,
                confidence=intel.confidence,
                source=intel.source,
                detail=intel.detail,
            )
        )
        if parsed.is_global:
            score += 6
        if intel.severity in {"high", "critical"}:
            score += 20
            reasoning_parts.append(f"IP {ip} has a high-risk reputation signal.")

    for cve in cves:
        intel = lookup_cve(cve)
        indicators.append(
            Indicator(
                kind="cve",
                value=cve,
                severity=intel.severity,
                confidence=intel.confidence,
                source=intel.source,
                detail=intel.detail,
            )
        )
        score += 30
        reasoning_parts.append(f"CVE {cve} indicates vulnerability-linked activity.")
        remediation.append(f"Validate whether systems exposed to {cve} are patched and inventoried.")

    if hashes:
        for digest in hashes:
            indicators.append(
                Indicator(
                    kind="hash",
                    value=digest,
                    severity="medium",
                    confidence=35,
                    source="pattern",
                    detail="Observed file hash; enrich with malware intelligence in the next milestone.",
                )
            )
        score += min(15, len(hashes) * 5)

    if failed_logins >= 3:
        score += 20
        reasoning_parts.append(f"{failed_logins} authentication failures were observed.")
        remediation.append("Check for brute-force attempts, password spraying, or account lockout activity.")

    if COMMAND_PATTERN.search(lower_blob):
        score += 18
        reasoning_parts.append("Potential command execution or scripting activity was detected.")
        remediation.append("Review whether the command is expected for the host or user role.")
        techniques = map_command_to_technique(log_text)
        for technique in techniques:
            indicators.append(
                Indicator(
                    kind="attack-technique",
                    value=technique["technique_id"],
                    severity="medium",
                    confidence=technique["confidence"],
                    source=technique["source"],
                    detail=technique["technique_name"],
                )
            )

    if MALWARE_PATTERN.search(lower_blob):
        score += 25
        reasoning_parts.append("Malware or intrusion terminology was observed in the log text.")
        remediation.append("Escalate to malware triage and isolate the host if the signal is corroborated.")

    if "privilege" in lower_blob or "sudo" in lower_blob or "admin" in lower_blob:
        score += 10
        remediation.append("Verify whether privileged activity is approved and logged.")

    if len(set(ips)) >= 3:
        score += 10
        remediation.append("Correlate the destinations with DNS, proxy, and firewall telemetry.")

    if not remediation:
        remediation.append("Continue monitoring and compare against the baseline for this asset or user.")

    severity = _severity_from_score(score)
    title = _title_from_hits(lines, cves, ips)
    detection_summary = (
        f"Analyzed {len(lines)} log lines from {source_name}. "
        f"Found {len(ips)} IPs, {len(cves)} CVEs, {len(hashes)} hashes, and {failed_logins} authentication failures."
    )
    reasoning = " ".join(reasoning_parts) if reasoning_parts else "No high-confidence malicious pattern was detected, but the log still deserves analyst review."

    if not indicators and not evidence:
        score = min(score, 20)
        severity = _severity_from_score(score)

    return AnalysisResult(
        title=title,
        severity=severity,
        risk_score=min(score, 100),
        detection_summary=detection_summary,
        reasoning=reasoning,
        indicators=indicators,
        evidence=evidence,
        remediation=remediation,
        model_notes="Heuristic vertical-slice analyzer",
    )

