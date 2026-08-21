"""Thread-safe shared knowledge storage for a scan."""

from __future__ import annotations

import asyncio
from copy import deepcopy
from typing import Any

from .retrieval import LocalRetriever, RetrievalDocument, RetrievalResult


class KnowledgeBase:
    def __init__(self) -> None:
        self._data: dict[str, Any] = {}
        self._lock = asyncio.Lock()

    async def update(self, values: dict[str, Any]) -> None:
        async with self._lock:
            for key, value in values.items():
                if isinstance(value, list) and isinstance(self._data.get(key), list):
                    self._data[key].extend(value)
                else:
                    self._data[key] = deepcopy(value)

    async def set(self, key: str, value: Any) -> None:
        await self.update({key: value})

    async def get(self, key: str, default: Any = None) -> Any:
        async with self._lock:
            return deepcopy(self._data.get(key, default))

    async def snapshot(self) -> dict[str, Any]:
        async with self._lock:
            return deepcopy(self._data)

    async def restore(self, values: dict[str, Any]) -> None:
        async with self._lock:
            self._data = deepcopy(values)

    async def retrieve(
        self, query: str, *, top_k: int = 5, min_score: float = 0.0
    ) -> list[RetrievalResult]:
        """Find relevant non-secret text from the current scan knowledge.

        Retrieval is intentionally limited to explicit snapshot values and
        skips fields commonly used for credentials or secrets.
        """
        snapshot = await self.snapshot()
        documents: list[RetrievalDocument] = []
        for key, value in snapshot.items():
            if any(
                secret in key.lower()
                for secret in ("credential", "password", "secret", "token", "api_key")
            ):
                continue
            text = value if isinstance(value, str) else repr(value)
            documents.append(RetrievalDocument(document_id=key, text=f"{key}: {text}"))
        return LocalRetriever(documents).search(query, top_k=top_k, min_score=min_score)
