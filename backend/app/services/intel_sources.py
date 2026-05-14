from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import requests

from app.core.settings import settings


@dataclass(slots=True)
class IntelDocument:
    doc_id: str
    title: str
    source: str
    text: str
    metadata: dict[str, Any]


def load_cisa_kev() -> list[IntelDocument]:
    response = requests.get(settings.cisa_kev_url, timeout=15)
    response.raise_for_status()
    payload = response.json()
    vulns = payload.get("vulnerabilities", [])
    docs: list[IntelDocument] = []
    for item in vulns[:1000]:
        cve = item.get("cveID", "")
        title = f"CISA KEV: {cve}"
        text = json.dumps(item, ensure_ascii=False)
        docs.append(
            IntelDocument(
                doc_id=f"cisa-kev::{cve}",
                title=title,
                source="cisa-kev",
                text=text,
                metadata={
                    "cve": cve,
                    "vendorProject": item.get("vendorProject", ""),
                    "product": item.get("product", ""),
                    "dateAdded": item.get("dateAdded", ""),
                    "dueDate": item.get("dueDate", ""),
                },
            )
        )
    return docs


def load_mitre_attack_notes() -> list[IntelDocument]:
    # Minimal free corpus starter for the RAG index.
    notes = [
        IntelDocument(
            doc_id="attack::T1059.001",
            title="MITRE ATT&CK T1059.001 PowerShell",
            source="mitre-attack",
            text="PowerShell is a common command and scripting interpreter used for living-off-the-land execution and defense evasion.",
            metadata={"technique_id": "T1059.001", "tactic": "Execution"},
        ),
        IntelDocument(
            doc_id="attack::T1003",
            title="MITRE ATT&CK T1003 OS Credential Dumping",
            source="mitre-attack",
            text="Credential dumping targets operating system credential stores and can enable lateral movement and privilege escalation.",
            metadata={"technique_id": "T1003", "tactic": "Credential Access"},
        ),
    ]
    return notes

