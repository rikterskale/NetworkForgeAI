"""
Google Model Adapter - Integration with Google Generative AI (Gemini).

Supports:
- Gemini Pro, Gemini Ultra
- Gemini 1.5 family
- Function calling
- Streaming responses
- Vision capabilities
"""

import asyncio
from typing import Any, AsyncIterator, Dict, List, Optional, cast

try:
    import google.generativeai as genai

    GOOGLE_AVAILABLE = True
except ImportError:
    GOOGLE_AVAILABLE = False

from .base_adapter import (
    BaseAdapter,
    Message,
    ModelCapability,
    ModelConfig,
    ModelProvider,
    ModelResponse,
    ToolDefinition,
)


class GoogleAdapter(BaseAdapter):
    """
    Adapter for Google's Gemini API.

    Supports Gemini Pro, Ultra, and Gemini 1.5 models with function calling.
    """

    def __init__(self, config: ModelConfig):
        super().__init__(config)
        self.client = None
        self.model: Any | None = None

        # Set capabilities based on model
        if "gemini" in config.model_name.lower():
            self.config.capabilities = [
                ModelCapability.CHAT,
                ModelCapability.STREAMING,
                ModelCapability.FUNCTION_CALLING,
                ModelCapability.VISION,
                ModelCapability.JSON_MODE,
            ]

    async def connect(self) -> bool:
        """Establish connection to Google Generative AI."""
        if not GOOGLE_AVAILABLE:
            raise ImportError(
                "Google Generative AI package not installed. Run: pip install google-generativeai"
            )

        try:
            if not self.config.api_key:
                raise ValueError("Google API key required")

            self.model = cast(Any, genai).GenerativeModel(self.config.model_name)
            cast(Any, genai).configure(api_key=self.config.api_key)
            self._is_connected = True
            return True
        except Exception as e:
            self._is_connected = False
            raise ConnectionError(f"Failed to connect to Google Generative AI: {e}")

    async def disconnect(self) -> None:
        """Cleanup resources."""
        self.model = None
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
        """Send a chat request to Gemini."""
        if not self.model:
            await self.connect()
        if self.model is None:
            raise ConnectionError("Google model unavailable")

        # Build conversation history
        chat = self.model.start_chat(history=[])

        # Convert and send messages
        temperature = temperature or self.config.temperature
        max_tokens = max_tokens or self.config.max_tokens

        # Configure generation settings
        generation_config = genai.types.GenerationConfig(
            max_output_tokens=max_tokens,
            temperature=temperature,
            top_p=self.config.top_p,
        )

        # Add tools if provided
        if tools:
            gemini_tools = self._convert_tools(tools)
            response = await asyncio.to_thread(
                chat.send_message,
                self._build_prompt(messages),
                generation_config=generation_config,
                tools=gemini_tools,
            )
        else:
            response = await asyncio.to_thread(
                chat.send_message, self._build_prompt(messages), generation_config=generation_config
            )

        # Extract content
        content_text = response.text

        # Check for function calls
        tool_calls: list[dict[str, Any]] = []
        if hasattr(response, "candidates") and response.candidates:
            candidate = response.candidates[0]
            if hasattr(candidate, "content") and hasattr(candidate.content, "parts"):
                for part in candidate.content.parts:
                    if hasattr(part, "function_call") and part.function_call:
                        tool_calls.append(
                            {
                                "id": f"call_{len(tool_calls)}",
                                "type": "function",
                                "function": {
                                    "name": part.function_call.name,
                                    "arguments": dict(part.function_call.args),
                                },
                            }
                        )

        # Estimate token usage (Google doesn't always provide exact counts)
        prompt_tokens = self.estimate_tokens(self._build_prompt(messages))
        completion_tokens = self.estimate_tokens(content_text)

        # Build response
        model_response = ModelResponse(
            content=content_text,
            model=self.config.model_name,
            usage={
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
            finish_reason="stop",
            tool_calls=tool_calls if tool_calls else None,
            raw_response={"text": content_text},
        )

        # Track token usage
        self.token_usage.add(model_response)

        return model_response

    async def chat_stream(
        self,
        messages: List[Message],
        tools: Optional[List[ToolDefinition]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Stream a chat response from Gemini."""
        if not self.model:
            await self.connect()
        if self.model is None:
            raise ConnectionError("Google model unavailable")

        chat = self.model.start_chat(history=[])

        temperature = temperature or self.config.temperature
        max_tokens = max_tokens or self.config.max_tokens

        generation_config = genai.types.GenerationConfig(
            max_output_tokens=max_tokens,
            temperature=temperature,
            top_p=self.config.top_p,
        )

        prompt = self._build_prompt(messages)

        try:
            response = await asyncio.to_thread(
                chat.send_message, prompt, generation_config=generation_config, stream=True
            )

            for chunk in response:
                if hasattr(chunk, "text") and chunk.text:
                    yield chunk.text

        except Exception as e:
            raise RuntimeError(f"Google streaming request failed: {e}")

    def _build_prompt(self, messages: List[Message]) -> str:
        """Convert messages to a single prompt string for Gemini."""
        parts = []

        for msg in messages:
            if msg.role == "system":
                parts.append(f"System: {msg.content}")
            elif msg.role == "user":
                parts.append(f"User: {msg.content}")
            elif msg.role == "assistant":
                parts.append(f"Assistant: {msg.content}")
            elif msg.role == "tool":
                parts.append(f"Tool Result: {msg.content}")

        return "\n".join(parts)

    def _convert_tools(self, tools: List[ToolDefinition]) -> List[Dict[str, Any]]:
        """Convert tools to Gemini format."""
        gemini_tools = []

        for tool in tools:
            gemini_tools.append(
                {"name": tool.name, "description": tool.description, "parameters": tool.parameters}
            )

        return gemini_tools

    def estimate_tokens(self, text: str) -> int:
        """
        Estimate tokens for Gemini models.

        Gemini uses a similar tokenization approach.
        """
        num_chars = len(text)
        avg_tokens = num_chars / 4
        return int(avg_tokens) + 4


class AzureOpenAIAdapter(BaseAdapter):
    """
    Adapter for Azure OpenAI Service.

    Delegates to OpenAIAdapter with Azure-specific configuration.
    """

    def __init__(
        self,
        config: ModelConfig,
        azure_endpoint: str,
        azure_deployment: str,
        api_version: str = "2024-02-15-preview",
    ):
        # Import here to avoid circular dependency
        from .openai_adapter import OpenAIAdapter

        azure_config = ModelConfig(
            provider=ModelProvider.AZURE_OPENAI,
            model_name=config.model_name,
            api_key=config.api_key,
            api_base=azure_endpoint,
            max_tokens=config.max_tokens,
            temperature=config.temperature,
            capabilities=[
                ModelCapability.CHAT,
                ModelCapability.STREAMING,
                ModelCapability.TOOL_CALLING,
                ModelCapability.FUNCTION_CALLING,
                ModelCapability.JSON_MODE,
            ],
        )

        self.azure_adapter = OpenAIAdapter(
            azure_config,
            azure_deployment=azure_deployment,
            azure_endpoint=azure_endpoint,
            api_version=api_version,
        )

    async def connect(self) -> bool:
        """Connect to Azure OpenAI."""
        return await self.azure_adapter.connect()

    async def disconnect(self) -> None:
        """Disconnect from Azure OpenAI."""
        await self.azure_adapter.disconnect()

    def supports_capability(self, capability: ModelCapability) -> bool:
        """Check capabilities."""
        return self.azure_adapter.supports_capability(capability)

    async def chat(
        self,
        messages: List[Message],
        tools: Optional[List[ToolDefinition]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> ModelResponse:
        """Send chat to Azure OpenAI."""
        return await self.azure_adapter.chat(
            messages, tools=tools, temperature=temperature, max_tokens=max_tokens, **kwargs
        )

    async def chat_stream(
        self,
        messages: List[Message],
        tools: Optional[List[ToolDefinition]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Stream chat from Azure OpenAI."""
        async for chunk in self.azure_adapter.chat_stream(
            messages, tools=tools, temperature=temperature, max_tokens=max_tokens, **kwargs
        ):
            yield chunk

    @property
    def provider_name(self) -> str:
        return "azure_openai"

    @property
    def model_name(self) -> str:
        return self.azure_adapter.model_name
