"""
Azure OpenAI provider. Handles GPT-4.1, GPT-4o, GPT-5, and any
model deployed through Azure AI Foundry (including Kimi, DeepSeek via Azure).
"""
import time
import asyncio
import logging
from openai import AsyncAzureOpenAI
from llm.base_provider import BaseLLMProvider, LLMResponse

logger = logging.getLogger(__name__)


class AzureOpenAIProvider(BaseLLMProvider):
    def __init__(self, config):
        azure_cfg = config.llm.azure_openai
        secrets = config.secrets.azure_openai
        deployment = azure_cfg.deployments[azure_cfg.active_deployment]
    
        self._client = AsyncAzureOpenAI(
            api_key=secrets.get("api_key", ""),
            azure_endpoint=azure_cfg.endpoint,
            api_version=azure_cfg.api_version,
        )
        # Access as dict since deployments is a nested dict, not a dataclass
        self._deployment_name = deployment["deployment_name"]
        self._model = deployment["model"]
        self._max_retries = config.llm.max_retries
        self._timeout = config.llm.timeout_seconds

    @property
    def provider_name(self) -> str:
        return "azure_openai"

    async def complete(self, system_prompt, user_message,
                       response_format="json", max_tokens=1000, temperature=0.1) -> LLMResponse:
        fmt = {"type": "json_object"} if response_format == "json" else {"type": "text"}
        start = time.monotonic()
        for attempt in range(self._max_retries):
            try:
                resp = await asyncio.wait_for(
                    self._client.chat.completions.create(
                        model=self._deployment_name,
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_message},
                        ],
                        response_format=fmt,
                        max_tokens=max_tokens,
                        temperature=temperature,
                    ),
                    timeout=self._timeout,
                )
                return LLMResponse(
                    content=resp.choices[0].message.content,
                    provider=self.provider_name,
                    model=self._model,
                    tokens_used=resp.usage.total_tokens if resp.usage else 0,
                    latency_ms=int((time.monotonic() - start) * 1000),
                )
            except Exception as e:
                logger.warning(f"AzureOpenAI attempt {attempt+1} failed: {e}")
                if attempt < self._max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
        raise RuntimeError(f"AzureOpenAI failed after {self._max_retries} attempts")

    async def health_check(self) -> bool:
        try:
            r = await self._client.chat.completions.create(
                model=self._deployment_name,
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=5,
            )
            return bool(r.choices)
        except Exception:
            return False
