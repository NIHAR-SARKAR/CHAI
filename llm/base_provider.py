"""Abstract base class for all LLM providers."""
from abc import ABC, abstractmethod
from typing import Literal
from dataclasses import dataclass


@dataclass
class LLMResponse:
    content: str
    provider: str
    model: str
    tokens_used: int
    latency_ms: int


class BaseLLMProvider(ABC):
    """
    All providers implement this single interface.
    The rest of the application never touches provider SDKs directly.
    """

    @abstractmethod
    async def complete(
        self,
        system_prompt: str,
        user_message: str,
        response_format: Literal["text", "json"] = "json",
        max_tokens: int = 1000,
        temperature: float = 0.1,
    ) -> LLMResponse:
        """
        Send a completion request and return a normalized response.
        Always returns LLMResponse — never raises on retryable errors
        (retries handled internally per provider).
        """
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Verify the provider is reachable and credentials are valid."""
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable name e.g. 'azure_openai', 'anthropic'."""
        ...
