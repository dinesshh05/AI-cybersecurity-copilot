from __future__ import annotations

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from app.core.events import build_event, event_bus
from app.services.analyzer import analyze_log_text
from app.services.storage import create_case_record
from app.services.summarizer import build_summary

router = APIRouter(prefix="/logs", tags=["logs"])


@router.post("/upload")
async def upload_log(
    file: UploadFile | None = File(default=None),
    log_text: str = Form(default=""),
    source_name: str = Form(default="uploaded-log"),
) -> dict:
    if file is None and not log_text.strip():
        raise HTTPException(status_code=400, detail="Provide either a file or log_text.")

    raw_text = log_text
    if file is not None:
        content = await file.read()
        raw_text = content.decode("utf-8", errors="ignore")
        source_name = source_name or file.filename or "uploaded-log"

    analysis = analyze_log_text(raw_text, source_name=source_name)
    summary_payload = build_summary(analysis.title, analysis)
    case_id = create_case_record(analysis.title, source_name, raw_text, analysis, summary_payload["summary"])
    await event_bus.publish(
        build_event(
            "analysis.completed",
            {
                "case_id": case_id,
                "title": analysis.title,
                "severity": analysis.severity,
                "risk_score": analysis.risk_score,
                "summary": summary_payload["summary"],
            },
        )
    )

    response = {
        "case_id": case_id,
        "analysis": analysis.to_dict(),
        "summary": summary_payload,
    }
    return response
