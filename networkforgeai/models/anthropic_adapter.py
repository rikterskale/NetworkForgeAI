"""
Anthropic Model Adapter - Integration with Claude API.

Supports:
- Claude 3 family (Opus, Sonnet, Haiku)
- Claude 2.1 and earlier
- Tool use (beta)
- Streaming responses
"""

from typing import Any, AsyncIterator, Dict, List, Optional

try:
    from anthropic import AsyncAnthropic

    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

from .base_adapter import (
    BaseAdapter,
    Message,
    ModelCapability,
    ModelConfig,
    ModelProvider,
    ModelResponse,
    ToolDefinition,
)


class AnthropicAdapter(BaseAdapter):
    """
    Adapter for Anthropic's Claude API.

    Supports Claude 3 Opus, Sonnet, and Haiku models with tool use capabilities.
    """

    def __init__(self, config: ModelConfig):
        super().__init__(config)
        self.client: Optional[AsyncAnthropic] = None

        # Set capabilities based on model
        if "claude-3" in config.model_name.lower():
            self.config.capabilities = [
                ModelCapability.CHAT,
                ModelCapability.STREAMING,
                ModelCapability.TOOL_CALLING,
                ModelCapability.VISION,
                ModelCapability.JSON_MODE,
            ]
        else:
            self.config.capabilities = [ModelCapability.CHAT, ModelCapability.STREAMING]

    async def connect(self) -> bool:
        """Establish connection to Anthropic API."""
        if not ANTHROPIC_AVAILABLE:
            raise ImportError("Anthropic package not installed. Run: pip install anthropic")

        try:
            if not self.config.api_key:
                raise ValueError("Anthropic API key required")

            self.client = AsyncAnthropic(api_key=self.config.api_key)
            self._is_connected = True
            return True
        except Exception as e:
            self._is_connected = False
            raise ConnectionError(f"Failed to connect to Anthropic API: {e}")

    async def disconnect(self) -> None:
        """Close the client session."""
        if self.client:
            await self.client.close()
            self.client = None
        self._is_connected = False

    def supports_capability(self, capability: ModelCapability) -> bool:
        """Check if the model supports a capability."""
        return capability in self.config.capabilities

    async def chat(
        self,
        messages: List[Message],
        tools: Optional[List[ToolDefinition]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> ModelResponse:
        """Send a chat request to Anthropic."""
        if not self.client:
            await self.connect()
        if self.client is None:
            raise ConnectionError("Anthropic client unavailable")

        # Separate system message from conversation
        system_message = ""
        conversation_messages = []

        for msg in messages:
            if msg.role == "system":
                system_message = msg.content
            else:
                conversation_messages.append(msg)

        # Convert messages to Anthropic format
        anthropic_messages = self._convert_messages(conversation_messages)

        # Prepare parameters
        params: dict[str, Any] = {
            "model": self.config.model_name,
            "messages": anthropic_messages,
            "max_tokens": max_tokens or self.config.max_tokens,
        }

        # Add system message if present
        if system_message:
            params["system"] = system_message

        # Add temperature
        params["temperature"] = temperature or self.config.temperature

        # Add tool support if provided (Claude 3+)
        if tools and "claude-3" in self.config.model_name.lower():
            params["tools"] = [t.to_anthropic_format() for t in tools]

        # JSON mode support
        if kwargs.get("json_mode"):
            if not system_message:
                params["system"] = "Respond only with valid JSON."
            else:
                params["system"] = f"{params['system']}\n\nRespond only with valid JSON."

        try:
            response = await self.client.messages.create(**params)

            # Extract content
            content_text = ""
            tool_calls = []

            for block in response.content:
                if block.type == "text":
                    content_text += block.text
                elif block.type == "tool_use":
                    tool_calls.append(
                        {
                            "id": block.id,
                            "type": "function",
                            "function": {"name": block.name, "arguments": block.input},
                        }
                    )

            # Build response
            model_response = ModelResponse(
                content=content_text,
                model=response.model,
                usage={
                    "prompt_tokens": response.usage.input_tokens,
                    "completion_tokens": response.usage.output_tokens,
                    "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
                },
                finish_reason=response.stop_reason,
                tool_calls=tool_calls if tool_calls else None,
                raw_response=response.model_dump(),
            )

            # Track token usage
            self.token_usage.add(model_response)

            return model_response

        except Exception as e:
            raise RuntimeError(f"Anthropic chat request failed: {e}")

    async def chat_stream(
        self,
        messages: List[Message],
        tools: Optional[List[ToolDefinition]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Stream a chat response from Anthropic."""
        if not self.client:
            await self.connect()
        if self.client is None:
            raise ConnectionError("Anthropic client unavailable")

        # Separate system message
        system_message = ""
        conversation_messages = []

        for msg in messages:
            if msg.role == "system":
                system_message = msg.content
            else:
                conversation_messages.append(msg)

        anthropic_messages = self._convert_messages(conversation_messages)

        params: dict[str, Any] = {
            "model": self.config.model_name,
            "messages": anthropic_messages,
            "max_tokens": max_tokens or self.config.max_tokens,
            "stream": True,
        }

        if system_message:
            params["system"] = system_message

        params["temperature"] = temperature or self.config.temperature

        if tools and "claude-3" in self.config.model_name.lower():
            params["tools"] = [t.to_anthropic_format() for t in tools]

        try:
            async with self.client.messages.stream(**params) as stream:
                async for text in stream.text_stream:
                    yield text
        except Exception as e:
            raise RuntimeError(f"Anthropic streaming request failed: {e}")

    def _convert_messages(self, messages: List[Message]) -> List[Dict[str, Any]]:
        """Convert internal Message objects to Anthropic format."""
        result = []

        for msg in messages:
            if msg.role == "system":
                continue  # System handled separately

            # Anthropic uses "user" and "assistant" roles
            role = msg.role
            if role == "tool":
                role = "user"  # Tool responses come back as user messages

            anthropic_msg: Dict[str, Any] = {"role": role, "content": msg.content}

            # Handle tool calls in assistant messages
            if msg.tool_calls:
                content_blocks: list[dict[str, Any]] = (
                    [{"type": "text", "text": msg.content}] if msg.content else []
                )
                for tc in msg.tool_calls:
                    function_info = tc.get("function") or {}
                    content_blocks.append(
                        {
                            "type": "tool_use",
                            "id": str(tc.get("id") or ""),
                            "name": str(function_info.get("name") or ""),
                            "input": function_info.get("arguments", {}) or {},
                        }
                    )
                anthropic_msg["content"] = content_blocks

            # Handle tool call results
            if msg.tool_call_id:
                content_blocks = [
                    {"type": "tool_result", "tool_use_id": msg.tool_call_id, "content": msg.content}
                ]
                anthropic_msg["content"] = content_blocks

            result.append(anthropic_msg)

        return result

    def estimate_tokens(self, text: str) -> int:
        """
        Estimate tokens for Anthropic models.

        Claude uses a similar tokenization to GPT-4.
        """
        num_chars = len(text)
        avg_tokens = num_chars / 4
        return int(avg_tokens) + 4


class LocalLLMAdapter(BaseAdapter):
    """
    Adapter for local LLM providers (Ollama, LM Studio, vLLM).

    Uses OpenAI-compatible API interface for maximum compatibility.
    """

    def __init__(self, config: ModelConfig, base_url: str = "http://localhost:11434/v1"):
        # Override config with local settings
        local_config = ModelConfig(
            provider=ModelProvider.LOCAL,
            model_name=config.model_name,
            api_key=config.api_key or "ollama",  # Ollama doesn't require a key
            api_base=config.api_base or base_url,
            max_tokens=config.max_tokens,
            temperature=config.temperature,
            capabilities=[ModelCapability.CHAT, ModelCapability.STREAMING],
        )

        # Import here to avoid circular dependency
        from .openai_adapter import OpenAIAdapter

        self.openai_adapter = OpenAIAdapter(local_config)

    async def connect(self) -> bool:
        """Connect to local LLM endpoint."""
        return await self.openai_adapter.connect()

    async def disconnect(self) -> None:
        """Disconnect from local LLM."""
        await self.openai_adapter.disconnect()

    def supports_capability(self, capability: ModelCapability) -> bool:
        """Check capabilities - local models vary widely."""
        # Assume basic chat and streaming support
        return capability in [ModelCapability.CHAT, ModelCapability.STREAMING]

    async def chat(
        self,
        messages: List[Message],
        tools: Optional[List[ToolDefinition]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> ModelResponse:
        """Send chat to local LLM."""
        # Note: Most local LLMs don't support tool calling yet
        return await self.openai_adapter.chat(
            messages,
            tools=None,  # Disable tools for local models
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )

    async def chat_stream(
        self,
        messages: List[Message],
        tools: Optional[List[ToolDefinition]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Stream chat from local LLM."""
        async for chunk in self.openai_adapter.chat_stream(
            messages, tools=None, temperature=temperature, max_tokens=max_tokens, **kwargs
        ):
            yield chunk

    @property
    def provider_name(self) -> str:
        return "local"

    @property
    def model_name(self) -> str:
        return self.openai_adapter.model_name
