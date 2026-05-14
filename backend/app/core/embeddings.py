from __future__ import annotations

import hashlib
from functools import lru_cache
from math import sqrt

try:
    from sentence_transformers import SentenceTransformer
except Exception:  # pragma: no cover - optional dependency path
    SentenceTransformer = None  # type: ignore[assignment]

from app.core.settings import settings


@lru_cache(maxsize=1)
def get_model():
    if SentenceTransformer is None:
        return None
    try:
        return SentenceTransformer(settings.embedding_model)
    except Exception:
        return None


def _fallback_vector(text: str, dimensions: int = 256) -> list[float]:
    vector = [0.0] * dimensions
    for token in text.lower().split():
        digest = hashlib.sha1(token.encode("utf-8")).digest()
        index = int.from_bytes(digest[:4], "little") % dimensions
        vector[index] += 1.0
    norm = sqrt(sum(value * value for value in vector)) or 1.0
    return [value / norm for value in vector]


def embed_texts(texts: list[str]) -> list[list[float]]:
    model = get_model()
    if model is not None and hasattr(model, "encode"):
        embeddings = model.encode(texts, normalize_embeddings=True)
        return embeddings.tolist()
    return [_fallback_vector(text) for text in texts]


def embed_query(text: str) -> list[float]:
    return embed_texts([text])[0]
