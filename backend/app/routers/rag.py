from __future__ import annotations

from fastapi import APIRouter

from app.services.agent_orchestrator import answer_security_question
from app.services.rag import rebuild_knowledge_base, search_knowledge

router = APIRouter(prefix="/rag", tags=["rag"])


@router.post("/rebuild")
def rebuild() -> dict:
    return rebuild_knowledge_base()


@router.get("/search")
def search(query: str, limit: int = 5) -> dict:
    items = search_knowledge(query, limit=limit)
    return {"items": [{"doc_id": item.doc_id, "title": item.title, "source": item.source, "score": item.score, "text": item.text, "metadata": item.metadata} for item in items]}


@router.post("/ask")
def ask(question: str) -> dict:
    return answer_security_question(question)
