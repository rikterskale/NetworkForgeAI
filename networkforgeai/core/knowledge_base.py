"""Thread-safe shared knowledge storage for a scan."""

from __future__ import annotations

import asyncio
from copy import deepcopy
from typing import Any


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

