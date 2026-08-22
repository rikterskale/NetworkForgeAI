"""Live provider smoke tests (drift canary).

These make a real, minimal API round-trip per provider to catch SDK/provider
contract drift that the fake-client unit tests in ``test_model_adapters.py``
cannot see (renamed usage fields, new finish reasons, changed tool-call shapes,
auth/parameter rejections).

They are gated two ways so they never run in the normal gate or on a machine
without credentials:

- marked ``live_provider`` (registered in pyproject); the dedicated workflow
  selects them with ``pytest -m live_provider``.
- each test ``skipif`` the provider's key is absent, so a run without secrets
  simply skips instead of failing.

Assertions check the *contract* (non-empty content, populated usage/model),
never the model's wording, which is non-deterministic. Prompts are one line with
a tiny ``max_tokens`` so each run costs a fraction of a cent.
"""

from __future__ import annotations

import os

import pytest

from networkforgeai.models.base_adapter import Message
from networkforgeai.models.model_factory import ModelFactory

pytestmark = pytest.mark.live_provider

_PING = [Message(role="user", content="Reply with the single word: pong")]


async def _assert_roundtrip(provider: str) -> None:
    adapter = ModelFactory.create_from_env(override_provider=provider)
    try:
        resp = await adapter.chat(_PING, max_tokens=5)
        assert resp.content.strip(), "expected non-empty content"
        assert resp.model, "expected a populated model field"
        assert resp.total_tokens > 0, "expected usage accounting to be populated"
    finally:
        await adapter.disconnect()


@pytest.mark.skipif(not os.getenv("OPENAI_API_KEY"), reason="no OPENAI_API_KEY")
async def test_openai_live_roundtrip():
    await _assert_roundtrip("openai")


@pytest.mark.skipif(not os.getenv("ANTHROPIC_API_KEY"), reason="no ANTHROPIC_API_KEY")
async def test_anthropic_live_roundtrip():
    await _assert_roundtrip("anthropic")


@pytest.mark.skipif(not os.getenv("GOOGLE_API_KEY"), reason="no GOOGLE_API_KEY")
async def test_google_live_roundtrip():
    await _assert_roundtrip("google")


@pytest.mark.skipif(not os.getenv("OPENAI_API_KEY"), reason="no OPENAI_API_KEY")
async def test_openai_live_streaming():
    adapter = ModelFactory.create_from_env(override_provider="openai")
    await adapter.connect()
    try:
        chunks = [chunk async for chunk in adapter.chat_stream(_PING, max_tokens=5)]
        assert "".join(chunks).strip(), "expected streamed content"
    finally:
        await adapter.disconnect()
