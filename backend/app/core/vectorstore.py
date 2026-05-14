from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path

from app.core.settings import settings


def _dot(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def _norm(a: list[float]) -> float:
    return math.sqrt(sum(x * x for x in a)) or 1.0


def _cosine(a: list[float], b: list[float]) -> float:
    return _dot(a, b) / (_norm(a) * _norm(b))


@dataclass
class _StoredDoc:
    id: str
    document: str
    embedding: list[float]
    metadata: dict


class _SimpleCollection:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._docs: dict[str, _StoredDoc] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return
        for item in raw.get("docs", []):
            self._docs[item["id"]] = _StoredDoc(
                id=item["id"],
                document=item["document"],
                embedding=list(item["embedding"]),
                metadata=dict(item.get("metadata", {})),
            )

    def _save(self) -> None:
        payload = {
            "docs": [
                {
                    "id": doc.id,
                    "document": doc.document,
                    "embedding": doc.embedding,
                    "metadata": doc.metadata,
                }
                for doc in self._docs.values()
            ]
        }
        self.path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def upsert(self, ids, documents, embeddings, metadatas):
        for doc_id, document, embedding, metadata in zip(ids, documents, embeddings, metadatas):
            self._docs[doc_id] = _StoredDoc(doc_id, document, list(embedding), dict(metadata))
        self._save()

    def count(self):
        return len(self._docs)

    def query(self, query_embeddings, n_results=5):
        query_embedding = list(query_embeddings[0])
        scored = []
        for doc in self._docs.values():
            scored.append((doc, _cosine(query_embedding, doc.embedding)))
        scored.sort(key=lambda item: item[1], reverse=True)
        top = scored[:n_results]
        return {
            "ids": [[doc.id for doc, _ in top]],
            "documents": [[doc.document for doc, _ in top]],
            "metadatas": [[doc.metadata for doc, _ in top]],
            "distances": [[max(0.0, 1.0 - score) for _, score in top]],
        }


def get_client():
    settings.vector_dir.mkdir(parents=True, exist_ok=True)
    try:
        import chromadb

        return chromadb.PersistentClient(path=str(settings.vector_dir))
    except Exception:
        return None


def get_collection(name: str = "cyber_knowledge"):
    client = get_client()
    if client is None:
        return _SimpleCollection(settings.vector_dir / f"{name}.json")
    return client.get_or_create_collection(
        name=name,
        metadata={"hnsw:space": "cosine"},
    )
