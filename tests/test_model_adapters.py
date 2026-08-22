"""Unit tests for the concrete LLM SDK adapters using fake clients.

The only network boundary in each adapter is a single client call; these tests
inject fake clients so every pure path — capability selection, message/tool
conversion, request assembly, response mapping, token accounting, streaming, and
error handling — is exercised without credentials or network access.
"""

from __future__ import annotations

import asyncio

import pytest

from networkforgeai.models import anthropic_adapter as anth_mod
from networkforgeai.models import google_adapter as google_mod
from networkforgeai.models import openai_adapter as openai_mod
from networkforgeai.models.anthropic_adapter import AnthropicAdapter, LocalLLMAdapter
from networkforgeai.models.base_adapter import (
    Message,
    ModelCapability,
    ModelConfig,
    ModelProvider,
    ToolDefinition,
)
from networkforgeai.models.google_adapter import AzureOpenAIAdapter, GoogleAdapter
from networkforgeai.models.openai_adapter import LiteLLMAdapter, OpenAIAdapter


def run(coro):
    return asyncio.run(coro)


def cfg(provider, model, **kw):
    return ModelConfig(provider=provider, model_name=model, api_key="k", **kw)


TOOL = ToolDefinition(
    name="probe", description="d", parameters={"type": "object", "properties": {}}
)


# --------------------------------------------------------------------------- #
# OpenAI
# --------------------------------------------------------------------------- #
class _OAUsage:
    prompt_tokens, completion_tokens, total_tokens = 3, 5, 8


class _OAFunc:
    name, arguments = "probe", '{"x":1}'


class _OATool:
    id, function = "call_1", _OAFunc()


class _OAMessage:
    def __init__(self, content="hello", tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls


class _OAChoice:
    def __init__(self, msg, finish="stop"):
        self.message = msg
        self.finish_reason = finish


class _OACompletion:
    def __init__(self, msg):
        self.choices = [_OAChoice(msg)]
        self.model = "gpt-4"
        self.usage = _OAUsage()

    def model_dump(self):
        return {"id": "x"}


class _AsyncStream:
    def __init__(self, chunks):
        self._chunks = chunks

    def __aiter__(self):
        async def gen():
            for c in self._chunks:
                yield c

        return gen()


class _OAChunkDelta:
    def __init__(self, content):
        self.content = content


class _OAChunkChoice:
    def __init__(self, content):
        self.delta = _OAChunkDelta(content)


class _OAChunk:
    def __init__(self, content):
        self.choices = [_OAChunkChoice(content)]


class _FakeCompletions:
    def __init__(self, result):
        self._result = result
        self.kwargs = None

    async def create(self, **kwargs):
        self.kwargs = kwargs
        if kwargs.get("stream"):
            return _AsyncStream([_OAChunk("he"), _OAChunk(""), _OAChunk("llo")])
        return self._result


class _FakeOpenAIClient:
    def __init__(self, result):
        self.chat = type("C", (), {"completions": _FakeCompletions(result)})()
        self.closed = False

    async def close(self):
        self.closed = True


def test_openai_capabilities_and_estimate():
    std = OpenAIAdapter(cfg(ModelProvider.OPENAI, "gpt-4"))
    assert std.supports_capability(ModelCapability.STREAMING)
    o1 = OpenAIAdapter(cfg(ModelProvider.OPENAI, "o1-preview"))
    assert not o1.supports_capability(ModelCapability.STREAMING)
    assert std.estimate_tokens("abcdefgh") == 6  # 8//4 + 4


def test_openai_chat_maps_response_and_tracks_usage():
    adapter = OpenAIAdapter(cfg(ModelProvider.OPENAI, "gpt-4"))
    adapter.client = _FakeOpenAIClient(_OACompletion(_OAMessage("hi", [_OATool()])))
    resp = run(adapter.chat([Message(role="user", content="q")], tools=[TOOL], json_mode=True))
    assert resp.content == "hi"
    assert resp.total_tokens == 8
    assert resp.tool_calls[0]["function"]["name"] == "probe"
    # json_mode + tools were forwarded to the SDK call.
    assert adapter.client.chat.completions.kwargs["response_format"] == {"type": "json_object"}
    assert adapter.client.chat.completions.kwargs["tools"]
    assert adapter.token_usage.total_tokens == 8


def test_openai_chat_o1_omits_temperature():
    adapter = OpenAIAdapter(cfg(ModelProvider.OPENAI, "o1-mini"))
    adapter.client = _FakeOpenAIClient(_OACompletion(_OAMessage()))
    run(adapter.chat([Message(role="user", content="q")]))
    assert "temperature" not in adapter.client.chat.completions.kwargs


def test_openai_chat_error_wrapped():
    class Boom(_FakeOpenAIClient):
        def __init__(self):
            super().__init__(None)

            async def raise_err(**kwargs):
                raise ValueError("nope")

            self.chat.completions.create = raise_err

    adapter = OpenAIAdapter(cfg(ModelProvider.OPENAI, "gpt-4"))
    adapter.client = Boom()
    with pytest.raises(RuntimeError, match="OpenAI chat request failed"):
        run(adapter.chat([Message(role="user", content="q")]))


def test_openai_stream_and_not_connected():
    adapter = OpenAIAdapter(cfg(ModelProvider.OPENAI, "gpt-4"))
    adapter.client = _FakeOpenAIClient(_OACompletion(_OAMessage()))

    async def collect():
        return [c async for c in adapter.chat_stream([Message(role="user", content="q")])]

    assert "".join(run(collect())) == "hello"

    disconnected = OpenAIAdapter(cfg(ModelProvider.OPENAI, "gpt-4"))

    async def drain():
        return [c async for c in disconnected.chat_stream([Message(role="user", content="q")])]

    with pytest.raises(RuntimeError, match="not connected"):
        run(drain())


def test_openai_convert_messages_and_extract_tool_calls():
    adapter = OpenAIAdapter(cfg(ModelProvider.OPENAI, "gpt-4"))
    converted = adapter._convert_messages(
        [
            Message(
                role="assistant", content="c", name="n", tool_call_id="tid", tool_calls=[{"a": 1}]
            )
        ]
    )
    assert converted[0]["name"] == "n" and converted[0]["tool_call_id"] == "tid"
    assert adapter._extract_tool_calls(None) == []
    assert adapter._extract_tool_calls([_OATool()])[0]["id"] == "call_1"


def test_openai_connect_paths(monkeypatch):
    created = {}

    class FakeAsyncOpenAI:
        def __init__(self, **kwargs):
            created.update(kwargs)

    monkeypatch.setattr(openai_mod, "AsyncOpenAI", FakeAsyncOpenAI)
    monkeypatch.setattr(openai_mod, "OPENAI_AVAILABLE", True)
    adapter = OpenAIAdapter(cfg(ModelProvider.OPENAI, "gpt-4"))
    assert run(adapter.connect()) is True
    assert created["api_key"] == "k"

    # Azure requires endpoint -> ConnectionError wrapping ValueError.
    azure = OpenAIAdapter(cfg(ModelProvider.AZURE_OPENAI, "gpt-4"))
    with pytest.raises(ConnectionError):
        run(azure.connect())

    # Import guard.
    monkeypatch.setattr(openai_mod, "OPENAI_AVAILABLE", False)
    with pytest.raises(ImportError):
        run(OpenAIAdapter(cfg(ModelProvider.OPENAI, "gpt-4")).connect())


def test_litellm_adapter(monkeypatch):
    monkeypatch.setattr(openai_mod, "AsyncOpenAI", lambda **kw: object())
    monkeypatch.setattr(openai_mod, "OPENAI_AVAILABLE", True)
    adapter = LiteLLMAdapter(cfg(ModelProvider.OPENAI, "anthropic/claude-3"))
    assert adapter.provider_name == "anthropic"
    assert run(adapter.connect()) is True
    monkeypatch.setattr(openai_mod, "OPENAI_AVAILABLE", False)
    with pytest.raises(ImportError):
        run(LiteLLMAdapter(cfg(ModelProvider.OPENAI, "x")).connect())


# --------------------------------------------------------------------------- #
# Anthropic
# --------------------------------------------------------------------------- #
class _AnthBlockText:
    type, text = "text", "answer"


class _AnthBlockTool:
    type, id, name, input = "tool_use", "tu_1", "probe", {"x": 1}


class _AnthUsage:
    input_tokens, output_tokens = 4, 6


class _AnthResponse:
    content = [_AnthBlockText(), _AnthBlockTool()]
    model = "claude-3-opus"
    stop_reason = "end_turn"
    usage = _AnthUsage()

    def model_dump(self):
        return {}


class _AnthMessages:
    def __init__(self):
        self.kwargs = None

    async def create(self, **kwargs):
        self.kwargs = kwargs
        return _AnthResponse()

    def stream(self, **kwargs):
        chunks = ["a", "b"]

        class Ctx:
            async def __aenter__(self_inner):
                async def gen():
                    for c in chunks:
                        yield c

                self_inner.text_stream = gen()
                return self_inner

            async def __aexit__(self_inner, *exc):
                return False

        return Ctx()


class _FakeAnthClient:
    def __init__(self):
        self.messages = _AnthMessages()


def test_anthropic_capabilities():
    c3 = AnthropicAdapter(cfg(ModelProvider.ANTHROPIC, "claude-3-opus"))
    assert c3.supports_capability(ModelCapability.VISION)
    legacy = AnthropicAdapter(cfg(ModelProvider.ANTHROPIC, "claude-2.1"))
    assert not legacy.supports_capability(ModelCapability.VISION)


def test_anthropic_chat_maps_blocks_and_system_and_json():
    adapter = AnthropicAdapter(cfg(ModelProvider.ANTHROPIC, "claude-3-opus"))
    adapter.client = _FakeAnthClient()
    resp = run(
        adapter.chat(
            [Message(role="system", content="sys"), Message(role="user", content="q")],
            tools=[TOOL],
            json_mode=True,
        )
    )
    assert resp.content == "answer"
    assert resp.total_tokens == 10
    assert resp.tool_calls[0]["function"]["name"] == "probe"
    assert "Respond only with valid JSON" in adapter.client.messages.kwargs["system"]
    assert adapter.client.messages.kwargs["tools"]


def test_anthropic_json_mode_without_system():
    adapter = AnthropicAdapter(cfg(ModelProvider.ANTHROPIC, "claude-3-opus"))
    adapter.client = _FakeAnthClient()
    run(adapter.chat([Message(role="user", content="q")], json_mode=True))
    assert adapter.client.messages.kwargs["system"] == "Respond only with valid JSON."


def test_anthropic_stream_and_convert_and_error():
    adapter = AnthropicAdapter(cfg(ModelProvider.ANTHROPIC, "claude-3-opus"))
    adapter.client = _FakeAnthClient()

    async def collect():
        return [t async for t in adapter.chat_stream([Message(role="user", content="q")])]

    assert "".join(run(collect())) == "ab"

    # _convert_messages: tool_calls and tool_call_id branches, tool role -> user.
    converted = adapter._convert_messages(
        [
            Message(
                role="assistant",
                content="c",
                tool_calls=[{"id": "1", "function": {"name": "f", "arguments": {}}}],
            ),
            Message(role="tool", content="r", tool_call_id="1"),
        ]
    )
    assert converted[0]["content"][0]["type"] == "text"
    assert converted[1]["role"] == "user"
    assert converted[1]["content"][0]["type"] == "tool_result"

    class Boom(_FakeAnthClient):
        def __init__(self):
            super().__init__()

            async def raise_err(**kwargs):
                raise ValueError("x")

            self.messages.create = raise_err

    adapter.client = Boom()
    with pytest.raises(RuntimeError, match="Anthropic chat request failed"):
        run(adapter.chat([Message(role="user", content="q")]))


def test_anthropic_connect(monkeypatch):
    monkeypatch.setattr(anth_mod, "ANTHROPIC_AVAILABLE", True)
    monkeypatch.setattr(anth_mod, "AsyncAnthropic", lambda **kw: object())
    assert run(AnthropicAdapter(cfg(ModelProvider.ANTHROPIC, "claude-3-opus")).connect()) is True
    # Missing key -> ConnectionError.
    no_key = AnthropicAdapter(ModelConfig(provider=ModelProvider.ANTHROPIC, model_name="claude-3"))
    with pytest.raises(ConnectionError):
        run(no_key.connect())
    monkeypatch.setattr(anth_mod, "ANTHROPIC_AVAILABLE", False)
    with pytest.raises(ImportError):
        run(AnthropicAdapter(cfg(ModelProvider.ANTHROPIC, "claude-3")).connect())


def test_local_llm_adapter_delegates():
    adapter = LocalLLMAdapter(cfg(ModelProvider.LOCAL, "llama3"))
    adapter.openai_adapter.client = _FakeOpenAIClient(_OACompletion(_OAMessage("local")))
    assert adapter.provider_name == "local"
    assert adapter.model_name == "llama3"
    assert adapter.supports_capability(ModelCapability.CHAT)
    resp = run(adapter.chat([Message(role="user", content="q")]))
    assert resp.content == "local"

    async def collect():
        return [c async for c in adapter.chat_stream([Message(role="user", content="q")])]

    assert "".join(run(collect())) == "hello"


# --------------------------------------------------------------------------- #
# Google
# --------------------------------------------------------------------------- #
class _GFunc:
    name, args = "probe", {"x": 1}


class _GPart:
    function_call = _GFunc()


class _GContent:
    parts = [_GPart()]


class _GCandidate:
    content = _GContent()


class _GResponse:
    text = "gem"
    candidates = [_GCandidate()]


class _GChunk:
    def __init__(self, text):
        self.text = text


class _GModels:
    def __init__(self):
        self.kwargs = None

    def generate_content(self, **kwargs):
        self.kwargs = kwargs
        return _GResponse()

    def generate_content_stream(self, **kwargs):
        return [_GChunk("g"), _GChunk(""), _GChunk("em")]


class _FakeGoogleClient:
    def __init__(self):
        self.models = _GModels()


def test_google_capabilities_prompt_and_estimate():
    adapter = GoogleAdapter(cfg(ModelProvider.GOOGLE, "gemini-1.5-pro"))
    assert adapter.supports_capability(ModelCapability.VISION)
    prompt = adapter._build_prompt(
        [
            Message(role="system", content="s"),
            Message(role="user", content="u"),
            Message(role="assistant", content="a"),
            Message(role="tool", content="t"),
        ]
    )
    assert "System: s" in prompt and "Tool Result: t" in prompt
    assert adapter.estimate_tokens("abcdefgh") == 6


def test_google_chat_maps_function_call_and_usage():
    adapter = GoogleAdapter(cfg(ModelProvider.GOOGLE, "gemini-1.5-pro"))
    adapter.client = _FakeGoogleClient()
    resp = run(adapter.chat([Message(role="user", content="q")]))
    assert resp.content == "gem"
    assert resp.tool_calls[0]["function"]["name"] == "probe"
    assert resp.total_tokens == resp.prompt_tokens + resp.completion_tokens


def test_google_stream_and_connect(monkeypatch):
    adapter = GoogleAdapter(cfg(ModelProvider.GOOGLE, "gemini-1.5-pro"))
    adapter.client = _FakeGoogleClient()

    async def collect():
        return [c async for c in adapter.chat_stream([Message(role="user", content="q")])]

    assert "".join(run(collect())) == "gem"

    monkeypatch.setattr(google_mod, "GOOGLE_AVAILABLE", True)
    monkeypatch.setattr(google_mod.genai, "Client", lambda **kw: object())
    assert run(GoogleAdapter(cfg(ModelProvider.GOOGLE, "gemini-1.5-pro")).connect()) is True
    no_key = GoogleAdapter(ModelConfig(provider=ModelProvider.GOOGLE, model_name="gemini-1.5-pro"))
    with pytest.raises(ConnectionError):
        run(no_key.connect())
    monkeypatch.setattr(google_mod, "GOOGLE_AVAILABLE", False)
    with pytest.raises(ImportError):
        run(GoogleAdapter(cfg(ModelProvider.GOOGLE, "gemini-1.5-pro")).connect())


def test_google_convert_tools():
    adapter = GoogleAdapter(cfg(ModelProvider.GOOGLE, "gemini-1.5-pro"))
    tools = adapter._convert_tools([TOOL])
    assert tools  # produces a genai Tool with one declaration


def test_openai_penalties_and_disconnect_and_azure_connect(monkeypatch):
    adapter = OpenAIAdapter(
        cfg(ModelProvider.OPENAI, "gpt-4", frequency_penalty=0.5, presence_penalty=0.3)
    )
    client = _FakeOpenAIClient(_OACompletion(_OAMessage()))
    adapter.client = client
    run(adapter.chat([Message(role="user", content="q")]))
    assert client.chat.completions.kwargs["frequency_penalty"] == 0.5
    assert client.chat.completions.kwargs["presence_penalty"] == 0.3
    run(adapter.disconnect())
    assert client.closed is True and adapter.client is None

    # Azure connect success path.
    monkeypatch.setattr(openai_mod, "OPENAI_AVAILABLE", True)
    monkeypatch.setattr(openai_mod, "AsyncAzureOpenAI", lambda **kw: object())
    azure = OpenAIAdapter(
        cfg(ModelProvider.AZURE_OPENAI, "gpt-4"),
        azure_endpoint="https://x.openai.azure.com",
        azure_deployment="dep",
    )
    assert run(azure.connect()) is True


def test_openai_stream_with_tools_and_error():
    adapter = OpenAIAdapter(cfg(ModelProvider.OPENAI, "gpt-4"))

    class Boom(_FakeOpenAIClient):
        def __init__(self):
            super().__init__(None)

            async def raise_err(**kwargs):
                raise ValueError("x")

            self.chat.completions.create = raise_err

    adapter.client = Boom()

    async def drain():
        return [
            c async for c in adapter.chat_stream([Message(role="user", content="q")], tools=[TOOL])
        ]

    with pytest.raises(RuntimeError, match="OpenAI streaming request failed"):
        run(drain())


def test_anthropic_and_google_disconnect():
    anth = AnthropicAdapter(cfg(ModelProvider.ANTHROPIC, "claude-3-opus"))

    class ClosableAnth(_FakeAnthClient):
        def __init__(self):
            super().__init__()
            self.closed = False

        async def close(self):
            self.closed = True

    anth.client = ClosableAnth()
    run(anth.disconnect())
    assert anth.client is None

    goog = GoogleAdapter(cfg(ModelProvider.GOOGLE, "gemini-1.5-pro"))
    goog.client = _FakeGoogleClient()
    run(goog.disconnect())
    assert goog.client is None


def test_google_stream_error():
    adapter = GoogleAdapter(cfg(ModelProvider.GOOGLE, "gemini-1.5-pro"))

    class Boom(_FakeGoogleClient):
        def __init__(self):
            super().__init__()

            def raise_err(**kwargs):
                raise ValueError("x")

            self.models.generate_content_stream = raise_err

    adapter.client = Boom()

    async def drain():
        return [c async for c in adapter.chat_stream([Message(role="user", content="q")])]

    with pytest.raises(RuntimeError, match="Google streaming request failed"):
        run(drain())


def test_azure_adapter_delegates():
    adapter = AzureOpenAIAdapter(
        cfg(ModelProvider.AZURE_OPENAI, "gpt-4"),
        azure_endpoint="https://x.openai.azure.com",
        azure_deployment="dep",
    )
    adapter.azure_adapter.client = _FakeOpenAIClient(_OACompletion(_OAMessage("azure")))
    assert adapter.provider_name == "azure_openai"
    assert adapter.model_name == "gpt-4"
    assert adapter.supports_capability(ModelCapability.CHAT)
    resp = run(adapter.chat([Message(role="user", content="q")]))
    assert resp.content == "azure"

    async def collect():
        return [c async for c in adapter.chat_stream([Message(role="user", content="q")])]

    assert "".join(run(collect())) == "hello"
