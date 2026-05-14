from __future__ import annotations

import json
import ipaddress
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


@dataclass(slots=True)
class IntelHit:
    kind: str
    value: str
    source: str
    label: str
    severity: str
    confidence: int
    detail: str
    references: list[str]

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "value": self.value,
            "source": self.source,
            "label": self.label,
            "severity": self.severity,
            "confidence": self.confidence,
            "detail": self.detail,
            "references": self.references,
        }


_SEED_IP_INTEL = {
    "185.220.101.1": IntelHit(
        kind="ip",
        value="185.220.101.1",
        source="local-seed",
        label="Known high-risk public IP example",
        severity="high",
        confidence=85,
        detail="Seeded indicator used to demonstrate suspicious IP analysis.",
        references=["local-seed://ip/185.220.101.1"],
    ),
}

_SEED_CVE_INTEL = {
    "CVE-2024-3094": IntelHit(
        kind="cve",
        value="CVE-2024-3094",
        source="local-seed",
        label="XZ Utils backdoor",
        severity="critical",
        confidence=99,
        detail="Widely discussed supply-chain compromise example.",
        references=["https://www.cve.org/CVERecord?id=CVE-2024-3094"],
    )
}

_COMMAND_TECHNIQUES = {
    "powershell": ("T1059.001", "PowerShell"),
    "mimikatz": ("T1003", "OS Credential Dumping"),
    "wget ": ("T1105", "Ingress Tool Transfer"),
    "curl ": ("T1105", "Ingress Tool Transfer"),
    "chmod 777": ("T1222", "File and Directory Permissions Modification"),
}


def lookup_ip_reputation(ip: str) -> IntelHit:
    if ip in _SEED_IP_INTEL:
        return _SEED_IP_INTEL[ip]
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return IntelHit(
            kind="ip",
            value=ip,
            source="validator",
            label="Invalid IP format",
            severity="low",
            confidence=0,
            detail="The value does not parse as a valid IPv4 or IPv6 address.",
            references=[],
        )
    if parsed.is_private or parsed.is_loopback or parsed.is_reserved:
        return IntelHit(
            kind="ip",
            value=ip,
            source="local-heuristic",
            label="Internal or non-routable address",
            severity="low",
            confidence=20,
            detail="This address is private, loopback, or reserved. It is unlikely to be an external threat indicator by itself.",
            references=[],
        )
    return IntelHit(
        kind="ip",
        value=ip,
        source="local-heuristic",
        label="Public IP observed in evidence",
        severity="medium",
        confidence=35,
        detail="This is a public address. Correlate with authentication failures, beaconing, or unusual destination patterns before treating it as malicious.",
        references=[],
    )


def lookup_cve(cve_id: str) -> IntelHit:
    if cve_id in _SEED_CVE_INTEL:
        return _SEED_CVE_INTEL[cve_id]

    query = urllib.parse.urlencode({"cveId": cve_id})
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}"
    request = urllib.request.Request(url, headers={"User-Agent": "AI-Cybersecurity-Copilot/0.1"})
    try:
        with urllib.request.urlopen(request, timeout=4) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError):
        return IntelHit(
            kind="cve",
            value=cve_id,
            source="fallback",
            label="CVE lookup unavailable",
            severity="medium",
            confidence=10,
            detail="The live NVD lookup did not succeed, so the case should be analyzed with local evidence and cached intel first.",
            references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
        )

    vulnerabilities = payload.get("vulnerabilities", [])
    if not vulnerabilities:
        return IntelHit(
            kind="cve",
            value=cve_id,
            source="nvd",
            label="CVE not found in the current response",
            severity="medium",
            confidence=20,
            detail="No enriched NVD record was returned. Check the CVE identifier formatting and whether the item is recently published.",
            references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
        )

    entry = vulnerabilities[0].get("cve", {})
    description_items = entry.get("descriptions", [])
    description = next(
        (item.get("value") for item in description_items if item.get("lang") == "en"),
        "No English description available.",
    )
    return IntelHit(
        kind="cve",
        value=cve_id,
        source="nvd",
        label=entry.get("id", cve_id),
        severity="medium",
        confidence=70,
        detail=description,
        references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
    )


def map_command_to_technique(command_blob: str) -> list[dict]:
    lower = command_blob.lower()
    matches: list[dict] = []
    for needle, (technique_id, technique_name) in _COMMAND_TECHNIQUES.items():
        if needle in lower:
            matches.append(
                {
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "source": "local-mapping",
                    "confidence": 70,
                }
            )
    return matches

