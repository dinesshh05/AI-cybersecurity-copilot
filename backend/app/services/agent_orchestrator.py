from __future__ import annotations

from app.services.rag import search_knowledge


def answer_security_question(question: str) -> dict:
    chunks = search_knowledge(question, limit=4)
    citations = [
        {
            "doc_id": chunk.doc_id,
            "title": chunk.title,
            "source": chunk.source,
            "score": chunk.score,
            "metadata": chunk.metadata,
        }
        for chunk in chunks
    ]
    if chunks:
        top_chunk = chunks[0]
        grounded_answer = (
            f"Top evidence from {top_chunk.source} suggests: {top_chunk.text[:320].rstrip()}. "
            f"This is relevant to your question: {question}"
        )
    else:
        grounded_answer = (
            "No strong retrieval match was found in the current free corpus. "
            f"Question: {question}"
        )
    return {
        "answer": grounded_answer,
        "citations": citations,
        "mode": "retrieval-first",
    }
