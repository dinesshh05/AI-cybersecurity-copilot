from __future__ import annotations

from app.services.rag import rebuild_knowledge_base


def seed_demo_corpus() -> dict:
    return rebuild_knowledge_base()

