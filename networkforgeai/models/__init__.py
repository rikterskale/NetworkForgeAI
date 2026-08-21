"""
NetworkForgeAI Models Package - LLM Adapter Layer

Provides unified interface to multiple LLM providers:
- OpenAI (GPT-4, o1)
- Anthropic (Claude 3)
- Google (Gemini)
- Azure OpenAI
- Local LLMs (Ollama, LM Studio, vLLM)
- LiteLLM unified interface

Usage:
    from networkforgeai.models import create_model

    # Create from environment variables
    adapter = create_model_from_env()

    # Or specify provider explicitly
    adapter = create_model(
        provider="openai",
        model_name="gpt-4",
        api_key="sk-..."
    )

    # Use the adapter
    await adapter.connect()
    response = await adapter.chat(messages=[...])
"""

from .ai_capabilities import (
    ERROR_RECOVERY_PROMPT,
    PLANNING_AGENT_PROMPT,
    RATE_LIMIT_RETRY_PROMPT,
    RECON_AGENT_PROMPT,
    REPORTING_AGENT_PROMPT,
    TOOL_SELECTION_PROMPT,
    VULN_SCANNER_AGENT_PROMPT,
    AgentPrompt,
    cot_attack_path_planning,
    cot_vulnerability_analysis,
    extract_findings_from_response,
    parse_json_response,
    summarize_conversation,
    truncate_context,
)
from .base_adapter import (
    BaseAdapter,
    Message,
    ModelCapability,
    ModelConfig,
    ModelProvider,
    ModelResponse,
    TokenUsage,
    ToolDefinition,
)
from .model_factory import (
    ModelFactory,
    create_model,
    create_model_from_env,
    get_available_providers,
)
from .retry import retry_async


# Lazy imports for specific adapters
def get_openai_adapter():
    from .openai_adapter import LiteLLMAdapter, OpenAIAdapter

    return OpenAIAdapter, LiteLLMAdapter


def get_anthropic_adapter():
    from .anthropic_adapter import AnthropicAdapter, LocalLLMAdapter

    return AnthropicAdapter, LocalLLMAdapter


def get_google_adapter():
    from .google_adapter import AzureOpenAIAdapter, GoogleAdapter

    return GoogleAdapter, AzureOpenAIAdapter


__all__ = [
    # Base classes
    "BaseAdapter",
    "ModelConfig",
    "ModelProvider",
    "ModelCapability",
    "Message",
    "ToolDefinition",
    "ModelResponse",
    "TokenUsage",
    # Factory
    "ModelFactory",
    "create_model",
    "create_model_from_env",
    "get_available_providers",
    # AI Capabilities
    "AgentPrompt",
    "RECON_AGENT_PROMPT",
    "VULN_SCANNER_AGENT_PROMPT",
    "PLANNING_AGENT_PROMPT",
    "REPORTING_AGENT_PROMPT",
    "cot_vulnerability_analysis",
    "cot_attack_path_planning",
    "TOOL_SELECTION_PROMPT",
    "parse_json_response",
    "extract_findings_from_response",
    "truncate_context",
    "summarize_conversation",
    "ERROR_RECOVERY_PROMPT",
    "RATE_LIMIT_RETRY_PROMPT",
    "retry_async",
]
