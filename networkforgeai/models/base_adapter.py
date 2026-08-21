"""
Base Model Adapter - Abstract foundation for all LLM providers.

Provides unified interface for:
- Chat completions
- Streaming responses
- Tool/function calling
- Context management
- Token tracking
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List, AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from .retry import retry_async


class ModelProvider(Enum):
    """Supported LLM providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    AZURE_OPENAI = "azure_openai"
    LOCAL = "local"
    LITELLM = "litellm"


class ModelCapability(Enum):
    """Capabilities a model may support."""
    CHAT = "chat"
    STREAMING = "streaming"
    TOOL_CALLING = "tool_calling"
    FUNCTION_CALLING = "function_calling"
    VISION = "vision"
    JSON_MODE = "json_mode"


@dataclass
class ModelConfig:
    """Configuration for a model."""
    provider: ModelProvider
    model_name: str
    api_key: Optional[str] = None
    api_base: Optional[str] = None
    max_tokens: int = 4096
    temperature: float = 0.7
    top_p: float = 1.0
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0
    timeout: int = 60
    capabilities: List[ModelCapability] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.capabilities:
            self.capabilities = [ModelCapability.CHAT]


@dataclass
class Message:
    """A chat message."""
    role: str  # "system", "user", "assistant", "tool"
    content: str
    name: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None
    tool_call_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        result = {"role": self.role, "content": self.content}
        if self.name:
            result["name"] = self.name
        if self.tool_calls:
            result["tool_calls"] = self.tool_calls
        if self.tool_call_id:
            result["tool_call_id"] = self.tool_call_id
        return result


@dataclass
class ToolDefinition:
    """Definition of a tool/function the model can call."""
    name: str
    description: str
    parameters: Dict[str, Any]
    
    def to_openai_format(self) -> Dict[str, Any]:
        """Convert to OpenAI function calling format."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters
            }
        }
    
    def to_anthropic_format(self) -> Dict[str, Any]:
        """Convert to Anthropic tool format."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.parameters
        }


@dataclass
class ModelResponse:
    """Response from an LLM."""
    content: str
    model: str
    usage: Dict[str, int]
    finish_reason: str
    tool_calls: Optional[List[Dict[str, Any]]] = None
    raw_response: Optional[Dict[str, Any]] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def prompt_tokens(self) -> int:
        return self.usage.get("prompt_tokens", 0)
    
    @property
    def completion_tokens(self) -> int:
        return self.usage.get("completion_tokens", 0)
    
    @property
    def total_tokens(self) -> int:
        return self.usage.get("total_tokens", 0)


@dataclass
class TokenUsage:
    """Token usage tracking."""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    session_tokens: int = 0
    
    def add(self, response: ModelResponse):
        """Add usage from a response."""
        self.prompt_tokens += response.prompt_tokens
        self.completion_tokens += response.completion_tokens
        self.total_tokens += response.total_tokens
        self.session_tokens += response.total_tokens
    
    def to_dict(self) -> Dict[str, int]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "session_tokens": self.session_tokens
        }


class BaseAdapter(ABC):
    """
    Abstract base class for all LLM adapters.
    
    Provides unified interface regardless of underlying provider.
    """
    
    def __init__(self, config: ModelConfig):
        self.config = config
        self.token_usage = TokenUsage()
        self.message_history: List[Message] = []
        self._is_connected = False
    
    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to the model provider."""
        pass
    
    @abstractmethod
    async def disconnect(self):
        """Close connection and cleanup resources."""
        pass
    
    @abstractmethod
    async def chat(
        self,
        messages: List[Message],
        tools: Optional[List[ToolDefinition]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> ModelResponse:
        """
        Send a chat request and get a response.
        
        Args:
            messages: List of chat messages
            tools: Optional list of available tools
            temperature: Override default temperature
            max_tokens: Override default max tokens
            
        Returns:
            ModelResponse with content and metadata
        """
        pass
    
    @abstractmethod
    async def chat_stream(
        self,
        messages: List[Message],
        tools: Optional[List[ToolDefinition]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> AsyncIterator[str]:
        """
        Stream a chat response.
        
        Yields chunks of text as they are generated.
        """
        pass
    
    @abstractmethod
    def supports_capability(self, capability: ModelCapability) -> bool:
        """Check if the model supports a specific capability."""
        pass
    
    def add_message(self, role: str, content: str, **kwargs):
        """Add a message to the conversation history."""
        msg = Message(role=role, content=content, **kwargs)
        self.message_history.append(msg)
    
    def clear_history(self):
        """Clear the conversation history."""
        self.message_history = []
    
    def get_history(self) -> List[Message]:
        """Get the conversation history."""
        return self.message_history.copy()
    
    def set_system_prompt(self, prompt: str):
        """Set or update the system prompt."""
        # Remove existing system message if present
        self.message_history = [m for m in self.message_history if m.role != "system"]
        # Add new system message at the beginning
        self.message_history.insert(0, Message(role="system", content=prompt))
    
    def estimate_tokens(self, text: str) -> int:
        """
        Estimate token count for text.
        
        Simple approximation: ~4 characters per token for English.
        Subclasses should override with provider-specific estimators.
        """
        return len(text) // 4
    
    def get_usage_summary(self) -> Dict[str, int]:
        """Get token usage summary."""
        return self.token_usage.to_dict()
    
    async def health_check(self) -> bool:
        """Check if the model is healthy and responsive."""
        try:
            test_messages = [Message(role="user", content="Hello")]
            response = await self.chat(test_messages, max_tokens=10)
            return response is not None and len(response.content) > 0
        except Exception:
            return False

    async def chat_with_retry(self, messages: List[Message], *, attempts: int = 3, **kwargs) -> ModelResponse:
        """Chat with bounded exponential backoff for transient provider failures."""
        return await retry_async(lambda: self.chat(messages, **kwargs), attempts=attempts)

    def prepare_context(self, messages: List[Message], max_tokens: int | None = None) -> List[Message]:
        """Apply the shared context policy while preserving system and recent messages."""
        limit = max_tokens or self.config.max_tokens
        total = 0
        selected: list[Message] = []
        for message in reversed(messages):
            estimate = self.estimate_tokens(message.content)
            if total + estimate > limit and selected:
                continue
            selected.append(message)
            total += estimate
        selected.reverse()
        systems = [message for message in messages if message.role == "system"]
        return systems + [message for message in selected if message.role != "system"]
    
    @property
    def is_connected(self) -> bool:
        """Check if adapter is connected."""
        return self._is_connected
    
    @property
    def provider_name(self) -> str:
        """Get the provider name."""
        return self.config.provider.value
    
    @property
    def model_name(self) -> str:
        """Get the model name."""
        return self.config.model_name
