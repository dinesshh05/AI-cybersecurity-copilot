from __future__ import annotations

import uuid
from datetime import datetime, timezone
from dataclasses import asdict

from app.core.db import get_connection, json_dump, json_load, row_to_dict
from app.models.domain import AnalysisResult


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_case_record(title: str, source_name: str, raw_text: str, analysis: AnalysisResult, summary: str) -> str:
    case_id = uuid.uuid4().hex
    analysis_id = uuid.uuid4().hex
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO cases (id, title, status, severity, risk_score, source_name, summary, raw_text, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                title,
                "open",
                analysis.severity,
                analysis.risk_score,
                source_name,
                summary,
                raw_text,
                utc_now(),
                utc_now(),
            ),
        )
        conn.execute(
            """
            INSERT INTO analyses (
                id, case_id, detection_summary, indicators_json, evidence_json, remediation_json, model_notes, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                analysis_id,
                case_id,
                analysis.detection_summary,
                json_dump([asdict(indicator) for indicator in analysis.indicators]),
                json_dump([asdict(item) for item in analysis.evidence]),
                json_dump(analysis.remediation),
                analysis.model_notes,
                utc_now(),
            ),
        )
        conn.execute(
            """
            INSERT INTO events (id, case_id, event_type, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                uuid.uuid4().hex,
                case_id,
                "analysis.completed",
                json_dump(
                    {
                        "case_id": case_id,
                        "severity": analysis.severity,
                        "risk_score": analysis.risk_score,
                        "summary": summary,
                    }
                ),
                utc_now(),
            ),
        )
    return case_id


def list_cases(limit: int = 50) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, title, status, severity, risk_score, source_name, summary, created_at, updated_at
            FROM cases
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [row_to_dict(row) for row in rows]


def get_case(case_id: str) -> dict | None:
    with get_connection() as conn:
        case_row = conn.execute(
            """
            SELECT id, title, status, severity, risk_score, source_name, summary, raw_text, created_at, updated_at
            FROM cases
            WHERE id = ?
            """,
            (case_id,),
        ).fetchone()
        if case_row is None:
            return None
        analysis_row = conn.execute(
            """
            SELECT detection_summary, indicators_json, evidence_json, remediation_json, model_notes, created_at
            FROM analyses
            WHERE case_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (case_id,),
        ).fetchone()
        event_rows = conn.execute(
            """
            SELECT event_type, payload_json, created_at
            FROM events
            WHERE case_id = ?
            ORDER BY created_at ASC
            """,
            (case_id,),
        ).fetchall()

    case = row_to_dict(case_row)
    if analysis_row is not None:
        analysis = row_to_dict(analysis_row)
        analysis["indicators"] = json_load(analysis["indicators_json"])
        analysis["evidence"] = json_load(analysis["evidence_json"])
        analysis["remediation"] = json_load(analysis["remediation_json"])
        del analysis["indicators_json"]
        del analysis["evidence_json"]
        del analysis["remediation_json"]
    else:
        analysis = None
    events = []
    for event_row in event_rows:
        event = row_to_dict(event_row)
        event["payload"] = json_load(event["payload_json"])
        del event["payload_json"]
        events.append(event)
    case["analysis"] = analysis
    case["events"] = events
    return case


def get_case_raw_text(case_id: str) -> str | None:
    with get_connection() as conn:
        row = conn.execute("SELECT raw_text FROM cases WHERE id = ?", (case_id,)).fetchone()
    if row is None:
        return None
    return row["raw_text"]


def seed_demo_case() -> str | None:
    existing = list_cases(limit=1)
    if existing:
        return None
    from app.services.analyzer import analyze_log_text
    from app.services.summarizer import build_summary

    demo_log = """Jan 14 08:15:11 auth host sshd[2321]: Failed password for invalid user admin from 185.220.101.1 port 52144 ssh2
Jan 14 08:15:12 auth host sshd[2321]: Failed password for invalid user root from 185.220.101.1 port 52145 ssh2
Jan 14 08:15:14 auth host sshd[2321]: Failed password for invalid user test from 185.220.101.1 port 52146 ssh2
Jan 14 08:16:03 endpoint powershell.exe -enc SQBFAFgAIAA=
Jan 14 08:16:06 endpoint kernel: malware beaconing to 203.0.113.42
Jan 14 08:16:07 scanner found CVE-2024-3094 on package xz-utils"""
    analysis = analyze_log_text(demo_log, source_name="seed-demo")
    summary_payload = build_summary("Seed demo incident", analysis)
    return create_case_record("Seed demo incident", "seed-demo", demo_log, analysis, summary_payload["summary"])
