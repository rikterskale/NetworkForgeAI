"""
Model Factory - Creates appropriate model adapters based on configuration.

Provides:
- Unified factory for creating adapters
- Provider detection and routing
- Fallback logic for failed connections
- Configuration from environment variables
"""

from typing import Optional, Dict, Any, Type
import os

from .base_adapter import (
    BaseAdapter, ModelConfig, ModelProvider, ModelCapability
)


class ModelFactory:
    """
    Factory for creating model adapters.
    
    Automatically selects the correct adapter based on provider configuration.
    Supports fallback chains for reliability.
    """
    
    # Registry of available adapters
    _adapters: Dict[ModelProvider, Type[BaseAdapter]] = {}
    
    @classmethod
    def register_adapter(cls, provider: ModelProvider, adapter_class: Type[BaseAdapter]):
        """Register an adapter class for a provider."""
        cls._adapters[provider] = adapter_class
    
    @classmethod
    def get_adapter(cls, provider: ModelProvider) -> Optional[Type[BaseAdapter]]:
        """Get the adapter class for a provider."""
        return cls._adapters.get(provider)
    
    @classmethod
    def create(
        cls,
        provider: str,
        model_name: str,
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
        **kwargs
    ) -> BaseAdapter:
        """
        Create a model adapter instance.
        
        Args:
            provider: Provider name (openai, anthropic, google, azure_openai, local, litellm)
            model_name: Model identifier (e.g., "gpt-4", "claude-3-opus")
            api_key: API key for the provider
            api_base: Optional base URL for custom endpoints
            **kwargs: Additional provider-specific arguments
            
        Returns:
            Configured adapter instance
            
        Raises:
            ValueError: If provider is not recognized
            ImportError: If required dependencies are missing
        """
        # Import adapters lazily to avoid circular dependencies
        from .openai_adapter import OpenAIAdapter, LiteLLMAdapter
        from .anthropic_adapter import AnthropicAdapter, LocalLLMAdapter
        from .google_adapter import GoogleAdapter, AzureOpenAIAdapter
        
        # Register all adapters
        cls.register_adapter(ModelProvider.OPENAI, OpenAIAdapter)
        cls.register_adapter(ModelProvider.ANTHROPIC, AnthropicAdapter)
        cls.register_adapter(ModelProvider.GOOGLE, GoogleAdapter)
        cls.register_adapter(ModelProvider.AZURE_OPENAI, AzureOpenAIAdapter)
        cls.register_adapter(ModelProvider.LOCAL, LocalLLMAdapter)
        cls.register_adapter(ModelProvider.LITELLM, LiteLLMAdapter)
        
        # Parse provider string
        provider_enum = cls._parse_provider(provider)
        
        if provider_enum not in cls._adapters:
            raise ValueError(
                f"Unknown provider: {provider}. "
                f"Supported providers: {[p.value for p in ModelProvider]}"
            )
        
        # Create config
        config = ModelConfig(
            provider=provider_enum,
            model_name=model_name,
            api_key=api_key,
            api_base=api_base,
            **kwargs
        )
        
        # Instantiate adapter
        adapter_class = cls._adapters[provider_enum]
        
        # Handle special cases
        if provider_enum == ModelProvider.AZURE_OPENAI:
            azure_endpoint = kwargs.get("azure_endpoint") or os.getenv("AZURE_OPENAI_ENDPOINT")
            azure_deployment = kwargs.get("azure_deployment") or model_name
            api_version = kwargs.get("api_version", "2024-02-15-preview")
            
            if not azure_endpoint:
                raise ValueError(
                    "Azure OpenAI requires AZURE_OPENAI_ENDPOINT environment variable "
                    "or azure_endpoint parameter"
                )
            
            return adapter_class(
                config,
                azure_endpoint=azure_endpoint,
                azure_deployment=azure_deployment,
                api_version=api_version
            )
        
        return adapter_class(config)
    
    @classmethod
    def create_from_env(cls, override_provider: Optional[str] = None) -> BaseAdapter:
        """
        Create an adapter from environment variables.
        
        Reads configuration from standard environment variables:
        - OPENAI_API_KEY, LITELLM_MODEL
        - ANTHROPIC_API_KEY, ANTHROPIC_MODEL
        - GOOGLE_API_KEY, GOOGLE_MODEL
        - AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_DEPLOYMENT, AZURE_OPENAI_API_KEY
        - LOCAL_LLM_URL, LOCAL_LLM_MODEL
        
        Args:
            override_provider: Force a specific provider
            
        Returns:
            Configured adapter instance
            
        Raises:
            ValueError: If no provider is configured
        """
        provider = override_provider
        
        # Detect provider from environment
        if not provider:
            if os.getenv("OPENAI_API_KEY"):
                provider = "openai"
            elif os.getenv("ANTHROPIC_API_KEY"):
                provider = "anthropic"
            elif os.getenv("GOOGLE_API_KEY"):
                provider = "google"
            elif os.getenv("AZURE_OPENAI_ENDPOINT") and os.getenv("AZURE_OPENAI_API_KEY"):
                provider = "azure_openai"
            elif os.getenv("LOCAL_LLM_URL"):
                provider = "local"
            else:
                raise ValueError(
                    "No LLM provider configured. Set one of:\n"
                    "- OPENAI_API_KEY\n"
                    "- ANTHROPIC_API_KEY\n"
                    "- GOOGLE_API_KEY\n"
                    "- AZURE_OPENAI_ENDPOINT + AZURE_OPENAI_API_KEY\n"
                    "- LOCAL_LLM_URL"
                )
        
        # Get model name
        model_name = os.getenv("LITELLM_MODEL", "openai/gpt-4")
        if provider == "anthropic":
            model_name = os.getenv("ANTHROPIC_MODEL", "claude-3-sonnet-20240229")
        elif provider == "google":
            model_name = os.getenv("GOOGLE_MODEL", "gemini-pro")
        elif provider == "local":
            model_name = os.getenv("LOCAL_LLM_MODEL", "llama2")
        elif provider == "openai":
            model_name = os.getenv("OPENAI_MODEL", "gpt-4")
        
        # Get API keys
        api_key = None
        if provider == "openai":
            api_key = os.getenv("OPENAI_API_KEY")
        elif provider == "anthropic":
            api_key = os.getenv("ANTHROPIC_API_KEY")
        elif provider == "google":
            api_key = os.getenv("GOOGLE_API_KEY")
        elif provider == "azure_openai":
            api_key = os.getenv("AZURE_OPENAI_API_KEY")
        elif provider == "local":
            api_key = os.getenv("LOCAL_LLM_API_KEY", "ollama")
        
        # Get base URL
        api_base = None
        if provider == "local":
            api_base = os.getenv("LOCAL_LLM_URL", "http://localhost:11434/v1")
        
        return cls.create(
            provider=provider,
            model_name=model_name,
            api_key=api_key,
            api_base=api_base
        )
    
    @classmethod
    def create_with_fallback(
        cls,
        providers: list[str],
        model_names: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> BaseAdapter:
        """
        Create an adapter with fallback chain.
        
        Tries each provider in order until one succeeds.
        
        Args:
            providers: List of provider names to try in order
            model_names: Optional dict mapping provider to model name
            **kwargs: Additional arguments
            
        Returns:
            First successful adapter instance
            
        Raises:
            ValueError: If all providers fail
        """
        model_names = model_names or {}
        last_error = None
        
        for provider in providers:
            try:
                model_name = model_names.get(provider, "gpt-4")
                adapter = cls.create(
                    provider=provider,
                    model_name=model_name,
                    **kwargs
                )
                
                # Test connection
                import asyncio
                try:
                    loop = asyncio.get_event_loop()
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                
                if loop.run_until_complete(adapter.connect()):
                    print(f"Successfully connected to {provider}")
                    return adapter
                    
            except Exception as e:
                last_error = e
                print(f"Failed to connect to {provider}: {e}")
                continue
        
        raise ValueError(
            f"All providers failed. Last error: {last_error}"
        )

    @classmethod
    async def create_with_fallback_async(
        cls, providers: list[str], model_names: Optional[Dict[str, str]] = None, **kwargs
    ) -> BaseAdapter:
        """Async-safe fallback creation for applications already inside an event loop."""
        model_names = model_names or {}
        last_error = None
        for provider in providers:
            try:
                adapter = cls.create(provider, model_names.get(provider, "gpt-4"), **kwargs)
                if await adapter.connect():
                    return adapter
            except Exception as exc:
                last_error = exc
        raise ValueError(f"All providers failed. Last error: {last_error}")
    
    @staticmethod
    def _parse_provider(provider: str) -> ModelProvider:
        """Parse provider string to enum."""
        provider_lower = provider.lower()
        
        provider_map = {
            "openai": ModelProvider.OPENAI,
            "anthropic": ModelProvider.ANTHROPIC,
            "google": ModelProvider.GOOGLE,
            "azure": ModelProvider.AZURE_OPENAI,
            "azure_openai": ModelProvider.AZURE_OPENAI,
            "local": ModelProvider.LOCAL,
            "litellm": ModelProvider.LITELLM,
            "ollama": ModelProvider.LOCAL,
            "lm_studio": ModelProvider.LOCAL,
            "vllm": ModelProvider.LOCAL,
        }
        
        return provider_map.get(provider_lower, ModelProvider.OPENAI)
    
    @classmethod
    def list_providers(cls) -> list[str]:
        """List all supported providers."""
        return [p.value for p in ModelProvider]
    
    @classmethod
    def get_capabilities(cls, provider: str) -> list[str]:
        """Get capabilities for a provider's default model."""
        provider_enum = cls._parse_provider(provider)
        
        capability_defaults = {
            ModelProvider.OPENAI: ["chat", "streaming", "tool_calling", "json_mode"],
            ModelProvider.ANTHROPIC: ["chat", "streaming", "tool_calling", "vision", "json_mode"],
            ModelProvider.GOOGLE: ["chat", "streaming", "function_calling", "vision", "json_mode"],
            ModelProvider.AZURE_OPENAI: ["chat", "streaming", "tool_calling", "json_mode"],
            ModelProvider.LOCAL: ["chat", "streaming"],
            ModelProvider.LITELLM: ["chat", "streaming", "tool_calling"],
        }
        
        return capability_defaults.get(provider_enum, ["chat"])


# Convenience functions
def create_model(
    provider: str,
    model_name: str,
    api_key: Optional[str] = None,
    **kwargs
) -> BaseAdapter:
    """Create a model adapter (convenience function)."""
    return ModelFactory.create(provider, model_name, api_key, **kwargs)


def create_model_from_env() -> BaseAdapter:
    """Create a model adapter from environment variables."""
    return ModelFactory.create_from_env()


def get_available_providers() -> list[str]:
    """Get list of available providers."""
    return ModelFactory.list_providers()
