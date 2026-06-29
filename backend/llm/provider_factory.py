"""
Reads config, returns the correct provider instance.
To add a new provider: create providers/myprovider.py, add one case here.
Nothing else changes.
"""
import logging
from llm.base_provider import BaseLLMProvider

logger = logging.getLogger(__name__)


def get_provider(config, provider_name: str | None = None) -> BaseLLMProvider:
    """
    Returns an instantiated provider. Uses config.llm.active_provider by default.
    Pass provider_name to override (e.g. for fallback logic).
    """
    name = provider_name or config.llm.active_provider

    match name:
        case "azure_openai":
            from llm.providers.azure_openai import AzureOpenAIProvider
            return AzureOpenAIProvider(config)
        case "openai":
            from llm.providers.openai_direct import OpenAIDirectProvider
            return OpenAIDirectProvider(config)
        case "anthropic":
            from llm.providers.anthropic_claude import AnthropicClaudeProvider
            return AnthropicClaudeProvider(config)
        case "amazon_bedrock":
            from llm.providers.amazon_bedrock import AmazonBedrockProvider
            return AmazonBedrockProvider(config)
        case "openrouter":
            from llm.providers.openrouter import OpenRouterProvider
            return OpenRouterProvider(config)
        case "huggingface":
            from llm.providers.huggingface import HuggingFaceProvider
            return HuggingFaceProvider(config)
        case _:
            raise ValueError(
                f"Unknown LLM provider: '{name}'. "
                f"Valid options: azure_openai, openai, anthropic, amazon_bedrock, openrouter, huggingface. "
                f"To add a new provider, create llm/providers/<name>.py and add a case here."
            )


async def get_provider_with_fallback(config) -> BaseLLMProvider:
    """
    Returns primary provider. If health check fails and fallback is configured,
    returns fallback provider instead.
    """
    primary = get_provider(config)
    if await primary.health_check():
        return primary
    fallback_name = config.llm.fallback_provider
    if fallback_name and fallback_name != config.llm.active_provider:
        logger.warning(f"Primary provider '{config.llm.active_provider}' unhealthy, switching to '{fallback_name}'")
        return get_provider(config, fallback_name)
    raise RuntimeError(f"LLM provider '{config.llm.active_provider}' is not reachable and no fallback configured")
