"""Small, deterministic local retrieval utilities for agent context."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

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
