from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.auth import CurrentUser, require_roles
from app.services.agent_orchestrator import answer_security_question
from app.services.rag import rebuild_knowledge_base, search_knowledge

router = APIRouter(prefix="/rag", tags=["rag"])


@router.post("/rebuild")
def rebuild(_: CurrentUser = Depends(require_roles("senior_analyst", "admin"))) -> dict:
    return rebuild_knowledge_base()


@router.get("/search")
def search(query: str, limit: int = 5, _: CurrentUser = Depends(require_roles("analyst", "senior_analyst", "admin"))) -> dict:
    items = search_knowledge(query, limit=limit)
    return {"items": [{"doc_id": item.doc_id, "title": item.title, "source": item.source, "score": item.score, "text": item.text, "metadata": item.metadata} for item in items]}


@router.post("/ask")
def ask(question: str, _: CurrentUser = Depends(require_roles("analyst", "senior_analyst", "admin"))) -> dict:
    return answer_security_question(question)
