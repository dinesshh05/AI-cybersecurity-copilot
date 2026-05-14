from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.core.embeddings import embed_query, embed_texts
from app.core.vectorstore import get_collection
from app.services.intel_sources import IntelDocument, load_cisa_kev, load_mitre_attack_notes


@dataclass(slots=True)
class RetrievedChunk:
    doc_id: str
    title: str
    source: str
    score: float
    text: str
    metadata: dict[str, Any]


def _seed_documents() -> list[IntelDocument]:
    docs = load_mitre_attack_notes()
    try:
        docs.extend(load_cisa_kev())
    except Exception:
        # Keep the project usable offline; free public sources are optional enrichments.
        pass
    return docs


def rebuild_knowledge_base() -> dict:
    collection = get_collection()
    docs = _seed_documents()
    texts = [doc.text for doc in docs]
    embeddings = embed_texts(texts)
    collection.upsert(
        ids=[doc.doc_id for doc in docs],
        documents=texts,
        embeddings=embeddings,
        metadatas=[{**doc.metadata, "title": doc.title, "source": doc.source} for doc in docs],
    )
    return {"indexed": len(docs)}


def search_knowledge(query: str, limit: int = 5) -> list[RetrievedChunk]:
    collection = get_collection()
    try:
        count = collection.count()
    except Exception:
        count = 0
    if count == 0:
        rebuild_knowledge_base()
    results = collection.query(query_embeddings=[embed_query(query)], n_results=limit)
    chunks: list[RetrievedChunk] = []
    ids = results.get("ids", [[]])[0]
    docs = results.get("documents", [[]])[0]
    metas = results.get("metadatas", [[]])[0]
    distances = results.get("distances", [[]])[0]
    for doc_id, text, meta, distance in zip(ids, docs, metas, distances):
        chunks.append(
            RetrievedChunk(
                doc_id=doc_id,
                title=meta.get("title", doc_id),
                source=meta.get("source", "unknown"),
                score=float(1.0 - distance),
                text=text,
                metadata=meta,
            )
        )
    return chunks
