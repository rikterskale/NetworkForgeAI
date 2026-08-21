"""Small, deterministic local retrieval utilities for agent context."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from math import sqrt
from typing import Any, Iterable, Sequence

_TOKEN_RE = re.compile(r"[a-zA-Z0-9_]{2,}")
_STOP_WORDS = {"and", "the", "this", "that", "with", "from", "for", "are"}


def _tokens(text: str) -> set[str]:
    return {token.lower() for token in _TOKEN_RE.findall(text) if token.lower() not in _STOP_WORDS}


@dataclass(frozen=True)
class RetrievalDocument:
    """A piece of explicitly supplied text that may be retrieved."""

    document_id: str
    text: str
    source: str = "knowledge_base"
    metadata: dict[str, Any] = field(default_factory=dict)
    embedding: tuple[float, ...] | None = None


@dataclass(frozen=True)
class RetrievalResult:
    """A matching document and its normalized lexical relevance score."""

    document: RetrievalDocument
    score: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "document_id": self.document.document_id,
            "text": self.document.text,
            "source": self.document.source,
            "metadata": dict(self.document.metadata),
            "score": round(self.score, 6),
        }


class LocalRetriever:
    """Dependency-free term-overlap retriever.

    It performs no network calls, model calls, or implicit data discovery. The
    caller controls exactly which documents are indexed.
    """

    def __init__(self, documents: Iterable[RetrievalDocument] = ()) -> None:
        self._documents = tuple(document for document in documents if document.text.strip())

    def search(
        self, query: str, *, top_k: int = 5, min_score: float = 0.0
    ) -> list[RetrievalResult]:
        """Return stable, best-first matches for ``query``."""
        if top_k <= 0:
            return []
        query_tokens = _tokens(query)
        if not query_tokens:
            return []

        matches: list[RetrievalResult] = []
        for document in self._documents:
            document_tokens = _tokens(document.text)
            overlap = query_tokens & document_tokens
            if not overlap:
                continue
            score = len(overlap) / len(query_tokens)
            if score >= min_score:
                matches.append(RetrievalResult(document=document, score=score))

        matches.sort(key=lambda result: (-result.score, result.document.document_id))
        return matches[:top_k]


class HybridRetriever(LocalRetriever):
    """Combine deterministic lexical matching with caller-supplied vectors.

    Vectors are optional and must be supplied by the caller. This class never
    contacts an embedding provider and falls back to lexical retrieval when a
    query vector or document vectors are unavailable.
    """

    def search(
        self,
        query: str,
        *,
        query_embedding: Sequence[float] | None = None,
        top_k: int = 5,
        min_score: float = 0.0,
        lexical_weight: float = 0.5,
        semantic_weight: float = 0.5,
    ) -> list[RetrievalResult]:
        if query_embedding is None or not any(document.embedding for document in self._documents):
            return super().search(query, top_k=top_k, min_score=min_score)
        if top_k <= 0 or lexical_weight < 0 or semantic_weight < 0:
            return []
        total_weight = lexical_weight + semantic_weight
        if total_weight == 0:
            return []

        query_tokens = _tokens(query)
        matches: list[RetrievalResult] = []
        for document in self._documents:
            semantic_score = _cosine_similarity(query_embedding, document.embedding)
            lexical_score = (
                len(query_tokens & _tokens(document.text)) / len(query_tokens)
                if query_tokens
                else 0.0
            )
            score = (
                lexical_weight * lexical_score + semantic_weight * semantic_score
            ) / total_weight
            if score >= min_score and score > 0:
                matches.append(RetrievalResult(document=document, score=score))
        matches.sort(key=lambda result: (-result.score, result.document.document_id))
        return matches[:top_k]


def _cosine_similarity(left: Sequence[float], right: Sequence[float] | None) -> float:
    """Return zero for incompatible or empty vectors instead of raising."""
    if right is None or len(left) != len(right) or not left:
        return 0.0
    left_norm = sqrt(sum(value * value for value in left))
    right_norm = sqrt(sum(value * value for value in right))
    if left_norm == 0 or right_norm == 0:
        return 0.0
    return max(0.0, min(1.0, sum(a * b for a, b in zip(left, right)) / (left_norm * right_norm)))
