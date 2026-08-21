"""
OpenAI Model Adapter - Integration with OpenAI API and compatible providers.

Supports:
- GPT-4, GPT-3.5, o1 models
- Azure OpenAI
- OpenAI-compatible APIs (local LLMs, etc.)
- Function/tool calling
- Streaming responses
"""

import asyncio
from typing import Optional, Dict, Any, List, AsyncIterator
from datetime import datetime

try:
    from openai import AsyncOpenAI, AsyncAzureOpenAI
    from openai.types import ChatModel
    from openai.types.chat import ChatCompletionMessageParam, ChatCompletionToolParam
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

from .base_adapter import (
    BaseAdapter, ModelConfig, ModelProvider, ModelCapability,
    Message, ToolDefinition, ModelResponse, TokenUsage
)


class OpenAIAdapter(BaseAdapter):
    """
    Adapter for OpenAI API and compatible providers.
    
    Supports GPT-4, GPT-3.5, o1, and OpenAI-compatible endpoints.
    """
    
    def __init__(
        self,
        config: ModelConfig,
        azure_deployment: Optional[str] = None,
        azure_endpoint: Optional[str] = None,
        api_version: str = "2024-02-15-preview"
    ):
        super().__init__(config)
        self.azure_deployment = azure_deployment
        self.azure_endpoint = azure_endpoint
        self.api_version = api_version
        self.client: Optional[AsyncOpenAI] = None
        
        # Set capabilities based on model
        if "o1" in config.model_name.lower():
            # o1 models have different capabilities
            self.config.capabilities = [
                ModelCapability.CHAT,
                ModelCapability.TOOL_CALLING,
                ModelCapability.JSON_MODE
            ]
        else:
            self.config.capabilities = [
                ModelCapability.CHAT,
                ModelCapability.STREAMING,
                ModelCapability.TOOL_CALLING,
                ModelCapability.FUNCTION_CALLING,
                ModelCapability.JSON_MODE
            ]
    
    async def connect(self) -> bool:
        """Establish connection to OpenAI API."""
        if not OPENAI_AVAILABLE:
            raise ImportError(
                "OpenAI package not installed. Run: pip install openai"
            )
        
        try:
            if self.config.provider == ModelProvider.AZURE_OPENAI:
                if not self.azure_endpoint or not self.config.api_key:
                    raise ValueError(
                        "Azure OpenAI requires endpoint and API key"
                    )
                self.client = AsyncAzureOpenAI(
                    azure_endpoint=self.azure_endpoint,
                    azure_deployment=self.azure_deployment or self.config.model_name,
                    api_key=self.config.api_key,
                    api_version=self.api_version
                )
            else:
                # Standard OpenAI or compatible provider
                self.client = AsyncOpenAI(
                    api_key=self.config.api_key,
                    base_url=self.config.api_base
                )
            
            self._is_connected = True
            return True
        except Exception as e:
            self._is_connected = False
            raise ConnectionError(f"Failed to connect to OpenAI API: {e}")
    
    async def disconnect(self):
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
        **kwargs
    ) -> ModelResponse:
        """Send a chat request to OpenAI."""
        if not self.client:
            await self.connect()
        
        # Convert messages to OpenAI format
        openai_messages = self._convert_messages(messages)
        
        # Prepare parameters
        params = {
            "model": self.azure_deployment or self.config.model_name,
            "messages": openai_messages,
            "max_tokens": max_tokens or self.config.max_tokens,
        }
        
        # Handle temperature (o1 models don't support temperature)
        if "o1" not in self.config.model_name.lower():
            params["temperature"] = temperature or self.config.temperature
        
        # Add tool support if provided
        if tools:
            params["tools"] = [t.to_openai_format() for t in tools]
            params["tool_choice"] = kwargs.get("tool_choice", "auto")
        
        # Add optional parameters
        if self.config.frequency_penalty:
            params["frequency_penalty"] = self.config.frequency_penalty
        if self.config.presence_penalty:
            params["presence_penalty"] = self.config.presence_penalty
        
        # JSON mode support
        if kwargs.get("json_mode"):
            params["response_format"] = {"type": "json_object"}
        
        try:
            response = await self.client.chat.completions.create(**params)
            
            # Extract content
            choice = response.choices[0]
            message = choice.message
            
            # Build response
            model_response = ModelResponse(
                content=message.content or "",
                model=response.model,
                usage={
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens
                },
                finish_reason=choice.finish_reason,
                tool_calls=self._extract_tool_calls(message.tool_calls) if message.tool_calls else None,
                raw_response=response.model_dump()
            )
            
            # Track token usage
            self.token_usage.add(model_response)
            
            return model_response
            
        except Exception as e:
            raise RuntimeError(f"OpenAI chat request failed: {e}")
    
    async def chat_stream(
        self,
        messages: List[Message],
        tools: Optional[List[ToolDefinition]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> AsyncIterator[str]:
        """Stream a chat response from OpenAI."""
        if not self.client:
            await self.connect()
        
        openai_messages = self._convert_messages(messages)
        
        params = {
            "model": self.azure_deployment or self.config.model_name,
            "messages": openai_messages,
            "max_tokens": max_tokens or self.config.max_tokens,
            "stream": True,
        }
        
        if "o1" not in self.config.model_name.lower():
            params["temperature"] = temperature or self.config.temperature
        
        if tools:
            params["tools"] = [t.to_openai_format() for t in tools]
        
        try:
            stream = await self.client.chat.completions.create(**params)
            
            async for chunk in stream:
                if chunk.choices and len(chunk.choices) > 0:
                    delta = chunk.choices[0].delta
                    if delta.content:
                        yield delta.content
                        
        except Exception as e:
            raise RuntimeError(f"OpenAI streaming request failed: {e}")
    
    def _convert_messages(
        self, 
        messages: List[Message]
    ) -> List[ChatCompletionMessageParam]:
        """Convert internal Message objects to OpenAI format."""
        result = []
        for msg in messages:
            openai_msg: ChatCompletionMessageParam = {
                "role": msg.role,  # type: ignore
                "content": msg.content
            }
            if msg.name:
                openai_msg["name"] = msg.name  # type: ignore
            if msg.tool_calls:
                openai_msg["tool_calls"] = msg.tool_calls  # type: ignore
            if msg.tool_call_id:
                openai_msg["tool_call_id"] = msg.tool_call_id  # type: ignore
            result.append(openai_msg)
        return result
    
    def _extract_tool_calls(
        self, 
        tool_calls: Any
    ) -> List[Dict[str, Any]]:
        """Extract tool calls from OpenAI response."""
        if not tool_calls:
            return []
        
        result = []
        for tc in tool_calls:
            result.append({
                "id": tc.id,
                "type": "function",
                "function": {
                    "name": tc.function.name,
                    "arguments": tc.function.arguments
                }
            })
        return result
    
    def estimate_tokens(self, text: str) -> int:
        """
        Estimate tokens using OpenAI's approximation.
        
        For GPT-4 and later: ~4 characters per token for English.
        More accurate than simple division.
        """
        # Simple heuristic - in production use tiktoken library
        num_chars = len(text)
        avg_tokens = num_chars / 4
        
        # Add overhead for message structure
        return int(avg_tokens) + 4


class LiteLLMAdapter(OpenAIAdapter):
    """
    Adapter using LiteLLM for unified multi-provider support.
    
    LiteLLM provides a single interface for OpenAI, Anthropic, Google, etc.
    This adapter uses LiteLLM's OpenAI-compatible interface.
    """
    
    def __init__(self, config: ModelConfig):
        # Force litellm provider
        litellm_config = ModelConfig(
            provider=ModelProvider.LITELLM,
            model_name=config.model_name,  # e.g., "anthropic/claude-3"
            api_key=config.api_key,
            api_base=config.api_base,
            max_tokens=config.max_tokens,
            temperature=config.temperature,
            capabilities=[
                ModelCapability.CHAT,
                ModelCapability.STREAMING,
                ModelCapability.TOOL_CALLING
            ]
        )
        super().__init__(litellm_config)
    
    async def connect(self) -> bool:
        """Connect via LiteLLM's OpenAI-compatible interface."""
        if not OPENAI_AVAILABLE:
            raise ImportError(
                "OpenAI package required for LiteLLM adapter. Run: pip install openai"
            )
        
        try:
            # LiteLLM exposes an OpenAI-compatible interface
            self.client = AsyncOpenAI(
                api_key=self.config.api_key,
                base_url=self.config.api_base or "https://proxy.litellm.ai"
            )
            self._is_connected = True
            return True
        except Exception as e:
            self._is_connected = False
            raise ConnectionError(f"Failed to connect via LiteLLM: {e}")
    
    @property
    def provider_name(self) -> str:
        """Get the actual provider from the model string."""
        # LiteLLM model strings are formatted as "provider/model-name"
        parts = self.config.model_name.split("/")
        return parts[0] if len(parts) > 1 else "litellm"
