"""
HuggingFace Inference API provider.
Uses HF's OpenAI-compatible router endpoint.
Automatically routes to best available inference provider (Cerebras, Groq, Together, etc.)
Token: HF_TOKEN or huggingface.api_key in .security.yml
"""
import time, asyncio, logging
from openai import AsyncOpenAI
from llm.base_provider import BaseLLMProvider, LLMResponse

logger = logging.getLogger(__name__)


class HuggingFaceProvider(BaseLLMProvider):
    def __init__(self, config):
        self._client = AsyncOpenAI(
            api_key=config.secrets.huggingface.get("api_key", ""),
            base_url=config.llm.huggingface.api_base,
        )
        self._model = config.llm.huggingface.model
        self._max_retries = config.llm.max_retries
        self._timeout = config.llm.timeout_seconds

    @property
    def provider_name(self) -> str:
        return "huggingface"

    async def complete(self, system_prompt, user_message,
                       response_format="json", max_tokens=1000, temperature=0.1) -> LLMResponse:
        sp = system_prompt
        if response_format == "json":
            sp += "\n\nRespond ONLY with a valid JSON object. No preamble, no markdown fences."
        start = time.monotonic()
        for attempt in range(self._max_retries):
            try:
                resp = await asyncio.wait_for(
                    self._client.chat.completions.create(
                        model=self._model,
                        messages=[
                            {"role": "system", "content": sp},
                            {"role": "user", "content": user_message},
                        ],
                        max_tokens=max_tokens,
                        temperature=temperature,
                        stream=False,
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
                logger.warning(f"HuggingFace attempt {attempt+1} failed: {e}")
                if attempt < self._max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
        raise RuntimeError("HuggingFace failed after retries")

    async def health_check(self) -> bool:
        try:
            r = await self._client.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=5,
            )
            return bool(r.choices)
        except Exception:
            return False
